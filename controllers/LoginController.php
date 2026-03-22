<?php

namespace Grocy\Controllers;

use Grocy\Services\SessionService;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;

class LoginController extends BaseController
{
	public function LoginPage(Request $request, Response $response, array $args)
	{
		$oidcEnabled = !empty(GROCY_OIDC_AUTHORITY) && !empty(GROCY_OIDC_CLIENT_ID);
		$oidcOnly = GROCY_AUTH_CLASS === 'Grocy\Middleware\OidcAuthMiddleware';
		$oidcProviderName = $oidcEnabled ? (parse_url(GROCY_OIDC_AUTHORITY, PHP_URL_HOST) ?: 'OIDC') : 'OIDC';

		return $this->renderPage($response, 'login', [
			'oidcEnabled'      => $oidcEnabled,
			'oidcOnly'         => $oidcOnly,
			'oidcProviderName' => $oidcProviderName,
		]);
	}

	public function Logout(Request $request, Response $response, array $args)
	{
		$this->getSessionService()->RemoveSession($_COOKIE[SessionService::SESSION_COOKIE_NAME]);
		return $response->withRedirect($this->AppContainer->get('UrlManager')->ConstructUrl('/'));
	}

	public function ProcessLogin(Request $request, Response $response, array $args)
	{
		$authMiddlewareClass = GROCY_AUTH_CLASS;
		if ($authMiddlewareClass::ProcessLogin($request->getParsedBody()))
		{
			return $response->withRedirect($this->AppContainer->get('UrlManager')->ConstructUrl('/'));
		}
		else
		{
			return $response->withRedirect($this->AppContainer->get('UrlManager')->ConstructUrl('/login?invalid=true'));
		}
	}
}
