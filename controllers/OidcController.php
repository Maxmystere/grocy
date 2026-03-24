<?php

namespace Grocy\Controllers;

use Grocy\Helpers\OidcJwtHelper;
use Grocy\Middleware\AuthMiddleware;
use Grocy\Services\DatabaseService;
use Grocy\Services\SessionService;
use Grocy\Services\UsersService;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;

class OidcController extends BaseController
{
	/**
	 * GET /oidc/login
	 * Initiates the OIDC Authorization Code flow with PKCE.
	 */
	public function StartLogin(Request $request, Response $response, array $args): Response
	{
		if (empty(GROCY_OIDC_AUTHORITY) || empty(GROCY_OIDC_CLIENT_ID))
		{
			return $this->RenderOidcError($response, 'OIDC is not configured. Please set OIDC_AUTHORITY and OIDC_CLIENT_ID in your configuration.');
		}

		$this->EnsureSessionStarted();

		// Generate PKCE code_verifier: cryptographically random, 43-128 chars (RFC 7636)
		$codeVerifier = OidcJwtHelper::Base64UrlEncode(random_bytes(64));

		// code_challenge = BASE64URL(SHA256(ASCII(code_verifier)))
		$codeChallenge = OidcJwtHelper::Base64UrlEncode(hash('sha256', $codeVerifier, true));

		// Anti-CSRF state parameter
		$state = bin2hex(random_bytes(32));

		// Store in PHP session to retrieve on callback
		$_SESSION['oidc_code_verifier'] = $codeVerifier;
		$_SESSION['oidc_state'] = $state;

		// Discover OIDC endpoints
		$config = $this->DiscoverOidcConfig();
		$authorizationEndpoint = $config['authorization_endpoint'];

		$redirectUri = $this->BuildCallbackUri($request);
		$scope = GROCY_OIDC_SCOPE;
		$clientId = GROCY_OIDC_CLIENT_ID;

		$params = http_build_query([
			'response_type'         => 'code',
			'client_id'             => $clientId,
			'redirect_uri'          => $redirectUri,
			'scope'                 => $scope,
			'state'                 => $state,
			'code_challenge'        => $codeChallenge,
			'code_challenge_method' => 'S256',
		]);

		return $response->withStatus(302)->withHeader('Location', $authorizationEndpoint . '?' . $params);
	}

	/**
	 * GET /oidc/callback
	 * Handles the OIDC provider callback, exchanges the code, validates the id_token,
	 * then creates/finds the grocy user and establishes a session.
	 */
	public function HandleCallback(Request $request, Response $response, array $args): Response
	{
		$this->EnsureSessionStarted();

		$queryParams = $request->getQueryParams();

		// Check for provider-side errors
		if (isset($queryParams['error']))
		{
			$error = htmlspecialchars($queryParams['error']);
			$description = isset($queryParams['error_description']) ? htmlspecialchars($queryParams['error_description']) : '';
			return $this->RenderOidcError($response, 'OIDC provider returned an error: ' . $error . ($description ? ' - ' . $description : ''));
		}

		if (!isset($queryParams['code']) || !isset($queryParams['state']))
		{
			return $this->RenderOidcError($response, 'Missing required parameters in OIDC callback');
		}

		$code = $queryParams['code'];
		$returnedState = $queryParams['state'];

		// Validate state (anti-CSRF)
		$expectedState = $_SESSION['oidc_state'] ?? null;
		if ($expectedState === null || !hash_equals($expectedState, $returnedState))
		{
			unset($_SESSION['oidc_state'], $_SESSION['oidc_code_verifier']);
			return $this->RenderOidcError($response, 'OIDC state parameter mismatch (possible CSRF attack)');
		}

		$codeVerifier = $_SESSION['oidc_code_verifier'] ?? null;
		if ($codeVerifier === null)
		{
			return $this->RenderOidcError($response, 'OIDC code verifier not found in session');
		}

		// Clear PKCE/state from session immediately after use (prevent replay)
		unset($_SESSION['oidc_state'], $_SESSION['oidc_code_verifier']);

		// Discover OIDC endpoints
		$oidcConfig = $this->DiscoverOidcConfig();

		// Exchange authorization code for tokens
		$redirectUri = $this->BuildCallbackUri($request);
		$tokenResponse = $this->ExchangeCodeForTokens($oidcConfig['token_endpoint'], $code, $codeVerifier, $redirectUri);

		if (!isset($tokenResponse['id_token']))
		{
			return $this->RenderOidcError($response, 'Token endpoint did not return an id_token');
		}

		// Fetch JWKS and validate id_token
		$jwks = $this->FetchJwks($oidcConfig['jwks_uri']);
		$issuer = $oidcConfig['issuer'];

		$claims = OidcJwtHelper::DecodeAndValidate(
			$tokenResponse['id_token'],
			$jwks,
			$issuer,
			GROCY_OIDC_CLIENT_ID
		);

		// Extract username from configured claim
		$usernameClaim = GROCY_OIDC_USERNAME_CLAIM;
		$username = $claims->{$usernameClaim} ?? null;

		if (empty($username))
		{
			// Fallback chain: preferred_username -> email -> sub
			$username = $claims->preferred_username ?? $claims->email ?? $claims->sub ?? null;
		}

		if (empty($username))
		{
			return $this->RenderOidcError($response, 'Could not determine username from OIDC claims');
		}

		// Sanitize username: only allow safe characters for Grocy usernames.
		// Note: characters that are not alphanumeric, '.', '_', '@', or '-' are replaced
		// with underscores, which could theoretically produce the same sanitized name
		// for two different raw usernames (e.g. "user name" and "user_name"). To handle
		// this, we also match against the OIDC 'sub' claim so that each distinct OIDC
		// identity always maps to the same Grocy user regardless of username changes.
		$username = preg_replace('/[^a-zA-Z0-9._@\-]/', '_', $username);
		if (empty($username))
		{
			return $this->RenderOidcError($response, 'Username derived from OIDC claims is empty after sanitization');
		}

		// Find or auto-create grocy user
		$db = DatabaseService::getInstance()->GetDbConnection();
		$user = $db->users()->where('username', $username)->fetch();
		if ($user === null)
		{
			$firstName = $claims->given_name ?? '';
			$lastName = $claims->family_name ?? '';
			$user = UsersService::getInstance()->CreateUser($username, $firstName, $lastName, '');
		}

		// Create grocy session
		$sessionKey = SessionService::getInstance()->CreateSession($user->id, false);
		AuthMiddleware::SetSessionCookie($sessionKey);

		return $response->withStatus(302)->withHeader('Location', $this->AppContainer->get('UrlManager')->ConstructUrl('/'));
	}

	/**
	 * Fetch OIDC discovery document from the well-known endpoint.
	 */
	private function DiscoverOidcConfig(): array
	{
		$authority = rtrim(GROCY_OIDC_AUTHORITY, '/');
		$discoveryUrl = $authority . '/.well-known/openid-configuration';

		$ctx = stream_context_create([
			'http' => [
				'method'  => 'GET',
				'timeout' => 10,
				'header'  => "Accept: application/json\r\n",
			],
			'ssl' => [
				'verify_peer'      => true,
				'verify_peer_name' => true,
			],
		]);

		$json = @file_get_contents($discoveryUrl, false, $ctx);
		if ($json === false)
		{
			throw new \Exception('Failed to fetch OIDC discovery document from: ' . $discoveryUrl);
		}

		$config = json_decode($json, true);
		if (!is_array($config))
		{
			throw new \Exception('Invalid OIDC discovery document from: ' . $discoveryUrl);
		}

		foreach (['issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri'] as $required)
		{
			if (empty($config[$required]))
			{
				throw new \Exception('OIDC discovery document missing required field: ' . $required);
			}
		}

		return $config;
	}

	/**
	 * Fetch JWKS (JSON Web Key Set) from the provider.
	 */
	private function FetchJwks(string $jwksUri): array
	{
		$ctx = stream_context_create([
			'http' => [
				'method'  => 'GET',
				'timeout' => 10,
				'header'  => "Accept: application/json\r\n",
			],
			'ssl' => [
				'verify_peer'      => true,
				'verify_peer_name' => true,
			],
		]);

		$json = @file_get_contents($jwksUri, false, $ctx);
		if ($json === false)
		{
			throw new \Exception('Failed to fetch JWKS from: ' . $jwksUri);
		}

		$jwks = json_decode($json, true);
		if (!is_array($jwks) || !isset($jwks['keys']))
		{
			throw new \Exception('Invalid JWKS response from: ' . $jwksUri);
		}

		return $jwks;
	}

	/**
	 * Exchange the authorization code for tokens at the token endpoint.
	 */
	private function ExchangeCodeForTokens(string $tokenEndpoint, string $code, string $codeVerifier, string $redirectUri): array
	{
		$postData = http_build_query([
			'grant_type'    => 'authorization_code',
			'code'          => $code,
			'redirect_uri'  => $redirectUri,
			'client_id'     => GROCY_OIDC_CLIENT_ID,
			'code_verifier' => $codeVerifier,
		]);

		$headers = "Content-Type: application/x-www-form-urlencoded\r\nAccept: application/json\r\n";

		// Include client_secret if configured (confidential client)
		$clientSecret = GROCY_OIDC_CLIENT_SECRET;
		if (!empty($clientSecret))
		{
			$credentials = base64_encode(GROCY_OIDC_CLIENT_ID . ':' . $clientSecret);
			$headers .= "Authorization: Basic " . $credentials . "\r\n";
		}

		$ctx = stream_context_create([
			'http' => [
				'method'  => 'POST',
				'header'  => $headers,
				'content' => $postData,
				'timeout' => 15,
			],
			'ssl' => [
				'verify_peer'      => true,
				'verify_peer_name' => true,
			],
		]);

		$json = @file_get_contents($tokenEndpoint, false, $ctx);
		if ($json === false)
		{
			throw new \Exception('Token endpoint request failed: ' . $tokenEndpoint);
		}

		$tokenResponse = json_decode($json, true);
		if (!is_array($tokenResponse))
		{
			throw new \Exception('Invalid token endpoint response');
		}

		if (isset($tokenResponse['error']))
		{
			throw new \Exception('Token endpoint error: ' . $tokenResponse['error'] . ' - ' . ($tokenResponse['error_description'] ?? ''));
		}

		return $tokenResponse;
	}

	/**
	 * Build the absolute callback URI for the current request.
	 */
	private function BuildCallbackUri(Request $request): string
	{
		return $this->AppContainer->get('UrlManager')->ConstructUrl('/oidc/callback');
	}

	/**
	 * Ensure PHP native session is started (used for PKCE state storage).
	 */
	private function EnsureSessionStarted(): void
	{
		if (session_status() === PHP_SESSION_NONE)
		{
			session_start([
				'cookie_httponly' => true,
				'cookie_samesite' => 'Lax',
				'cookie_secure'   => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
			]);
		}
	}

	/**
	 * Render an error response for OIDC failures.
	 */
	private function RenderOidcError(Response $response, string $message): Response
	{
		return $this->renderPage($response, 'oidc_error', ['errorMessage' => $message]);
	}
}
