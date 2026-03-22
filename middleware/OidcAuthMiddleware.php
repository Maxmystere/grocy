<?php

namespace Grocy\Middleware;

use Grocy\Services\DatabaseService;
use Grocy\Services\UsersService;
use Psr\Http\Message\ServerRequestInterface as Request;

class OidcAuthMiddleware extends AuthMiddleware
{
	public function authenticate(Request $request)
	{
		define('GROCY_EXTERNALLY_MANAGED_AUTHENTICATION', true);

		// First try to authenticate by API key
		$auth = new ApiKeyAuthMiddleware($this->AppContainer, $this->ResponseFactory);
		$user = $auth->authenticate($request);
		if ($user !== null)
		{
			return $user;
		}

		// Then by session cookie
		$auth = new SessionAuthMiddleware($this->AppContainer, $this->ResponseFactory);
		$user = $auth->authenticate($request);
		return $user;
	}

	public static function ProcessLogin(array $postParams)
	{
		throw new \Exception('OidcAuthMiddleware does not support form-based login. Use the OIDC redirect flow via /oidc/login.');
	}
}
