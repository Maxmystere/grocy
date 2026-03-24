<?php

namespace Grocy\Helpers;

/**
 * Minimal OIDC JWT helper using PHP's built-in OpenSSL extension.
 * Supports RS256, RS384, RS512, ES256, ES384, ES512 algorithms.
 */
class OidcJwtHelper
{
	/** Allowable clock skew in seconds when validating the nbf (not before) claim. */
	const NBF_CLOCK_SKEW_TOLERANCE = 60;
	/**
	 * Decode and validate a JWT id_token.
	 *
	 * @param string $token The raw JWT string
	 * @param array  $jwks  The JWKS as a decoded PHP array (from json_decode)
	 * @param string $issuer Expected issuer (iss claim)
	 * @param string $audience Expected audience (aud claim, usually the client_id)
	 * @return \stdClass The decoded claims payload
	 * @throws \Exception on validation failure
	 */
	public static function DecodeAndValidate(string $token, array $jwks, string $issuer, string $audience): \stdClass
	{
		$parts = explode('.', $token);
		if (count($parts) !== 3)
		{
			throw new \Exception('Invalid JWT format');
		}

		[$headerB64, $payloadB64, $signatureB64] = $parts;

		$header = json_decode(self::Base64UrlDecode($headerB64));
		if ($header === null)
		{
			throw new \Exception('Invalid JWT header');
		}

		$payload = json_decode(self::Base64UrlDecode($payloadB64));
		if ($payload === null)
		{
			throw new \Exception('Invalid JWT payload');
		}

		$signature = self::Base64UrlDecode($signatureB64);

		// Verify signature
		$signingInput = $headerB64 . '.' . $payloadB64;
		self::VerifySignature($signingInput, $signature, $header, $jwks);

		// Validate standard claims
		if (isset($payload->iss) && $payload->iss !== $issuer)
		{
			throw new \Exception('JWT issuer mismatch: expected ' . $issuer . ', got ' . $payload->iss);
		}

		// aud can be a string or array
		$audiences = is_array($payload->aud ?? null) ? $payload->aud : [$payload->aud ?? ''];
		if (!in_array($audience, $audiences, true))
		{
			throw new \Exception('JWT audience mismatch');
		}

		if (isset($payload->exp) && $payload->exp < time())
		{
			throw new \Exception('JWT is expired');
		}

		if (isset($payload->nbf) && $payload->nbf > time() + self::NBF_CLOCK_SKEW_TOLERANCE)
		{
			throw new \Exception('JWT not yet valid');
		}

		return $payload;
	}

	/**
	 * Verify the JWT signature using OpenSSL.
	 */
	private static function VerifySignature(string $signingInput, string $signature, \stdClass $header, array $jwks): void
	{
		$algorithm = $header->alg ?? '';
		$kid = $header->kid ?? null;

		// Find matching key in JWKS
		$keys = $jwks['keys'] ?? [];
		$matchingKey = null;

		foreach ($keys as $key)
		{
			if ($kid !== null && ($key['kid'] ?? null) !== $kid)
			{
				continue;
			}

			$use = $key['use'] ?? 'sig';
			if ($use !== 'sig')
			{
				continue;
			}

			$matchingKey = $key;
			break;
		}

		if ($matchingKey === null)
		{
			// If no kid match, try any sig key
			foreach ($keys as $key)
			{
				if (($key['use'] ?? 'sig') === 'sig')
				{
					$matchingKey = $key;
					break;
				}
			}
		}

		if ($matchingKey === null)
		{
			throw new \Exception('No suitable key found in JWKS');
		}

		$kty = $matchingKey['kty'] ?? '';

		switch ($algorithm)
		{
			case 'RS256':
			case 'RS384':
			case 'RS512':
				if ($kty !== 'RSA')
				{
					throw new \Exception('Key type mismatch: expected RSA for ' . $algorithm);
				}
				$openSslAlgo = self::GetOpenSslAlgo($algorithm);
				$publicKey = self::JwkRsaToPublicKey($matchingKey);
				$result = openssl_verify($signingInput, $signature, $publicKey, $openSslAlgo);
				if ($result !== 1)
				{
					throw new \Exception('JWT signature verification failed');
				}
				break;

			case 'ES256':
			case 'ES384':
			case 'ES512':
				if ($kty !== 'EC')
				{
					throw new \Exception('Key type mismatch: expected EC for ' . $algorithm);
				}
				$openSslAlgo = self::GetOpenSslAlgo($algorithm);
				$publicKey = self::JwkEcToPublicKey($matchingKey);
				// Convert DER-encoded signature to OpenSSL format (ECDSA uses DER encoding)
				$derSig = self::EcdsaSignatureToDer($signature, $algorithm);
				$result = openssl_verify($signingInput, $derSig, $publicKey, $openSslAlgo);
				if ($result !== 1)
				{
					throw new \Exception('JWT EC signature verification failed');
				}
				break;

			default:
				throw new \Exception('Unsupported JWT algorithm: ' . $algorithm);
		}
	}

	private static function GetOpenSslAlgo(string $algorithm): int
	{
		switch ($algorithm)
		{
			case 'RS256':
			case 'ES256':
				return OPENSSL_ALGO_SHA256;
			case 'RS384':
			case 'ES384':
				return OPENSSL_ALGO_SHA384;
			case 'RS512':
			case 'ES512':
				return OPENSSL_ALGO_SHA512;
			default:
				throw new \Exception('Unsupported algorithm: ' . $algorithm);
		}
	}

	/**
	 * Convert RSA JWK to PEM public key using OpenSSL.
	 */
	private static function JwkRsaToPublicKey(array $jwk): \OpenSSLAsymmetricKey
	{
		$n = self::Base64UrlDecode($jwk['n']);
		$e = self::Base64UrlDecode($jwk['e']);

		// Build DER-encoded RSA public key (PKCS#1)
		$modulus = self::EncodeAsn1Integer($n);
		$exponent = self::EncodeAsn1Integer($e);

		$rsaPublicKey = self::Asn1Sequence($modulus . $exponent);

		// Wrap in SubjectPublicKeyInfo (PKCS#8 format)
		// RSA OID: 1.2.840.113549.1.1.1
		$rsaOid = "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00";
		$subjectPublicKeyInfo = self::Asn1Sequence($rsaOid . self::Asn1BitString($rsaPublicKey));

		$pem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($subjectPublicKeyInfo), 64, "\n") . "-----END PUBLIC KEY-----\n";

		$key = openssl_pkey_get_public($pem);
		if ($key === false)
		{
			throw new \Exception('Failed to parse RSA public key from JWK');
		}

		return $key;
	}

	/**
	 * Convert EC JWK to PEM public key using OpenSSL.
	 */
	private static function JwkEcToPublicKey(array $jwk): \OpenSSLAsymmetricKey
	{
		$crv = $jwk['crv'] ?? 'P-256';
		$x = self::Base64UrlDecode($jwk['x']);
		$y = self::Base64UrlDecode($jwk['y']);

		// OIDs for EC curves
		$curveOids = [
			'P-256' => "\x2a\x86\x48\xce\x3d\x03\x01\x07",
			'P-384' => "\x2b\x81\x04\x00\x22",
			'P-521' => "\x2b\x81\x04\x00\x23",
		];

		if (!isset($curveOids[$crv]))
		{
			throw new \Exception('Unsupported EC curve: ' . $crv);
		}

		$curveOid = $curveOids[$crv];

		// EC OID: 1.2.840.10045.2.1
		$ecOid = "\x2a\x86\x48\xce\x3d\x02\x01";

		$algorithmIdentifier = self::Asn1Sequence(
			self::Asn1ObjectIdentifier($ecOid) . self::Asn1ObjectIdentifier($curveOid)
		);

		// Uncompressed EC point: 0x04 || x || y
		$point = "\x04" . $x . $y;
		$subjectPublicKeyInfo = self::Asn1Sequence($algorithmIdentifier . self::Asn1BitString($point));

		$pem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($subjectPublicKeyInfo), 64, "\n") . "-----END PUBLIC KEY-----\n";

		$key = openssl_pkey_get_public($pem);
		if ($key === false)
		{
			throw new \Exception('Failed to parse EC public key from JWK');
		}

		return $key;
	}

	/**
	 * Convert ECDSA raw signature (r||s) to DER format for OpenSSL.
	 */
	private static function EcdsaSignatureToDer(string $signature, string $algorithm): string
	{
		$len = strlen($signature);
		$half = (int)($len / 2);

		$r = substr($signature, 0, $half);
		$s = substr($signature, $half);

		$rDer = self::EncodeAsn1Integer($r);
		$sDer = self::EncodeAsn1Integer($s);

		return self::Asn1Sequence($rDer . $sDer);
	}

	// --- ASN.1 helpers ---

	private static function Asn1Sequence(string $content): string
	{
		return "\x30" . self::Asn1Length($content) . $content;
	}

	private static function Asn1BitString(string $content): string
	{
		return "\x03" . self::Asn1Length("\x00" . $content) . "\x00" . $content;
	}

	private static function Asn1ObjectIdentifier(string $oid): string
	{
		return "\x06" . self::Asn1Length($oid) . $oid;
	}

	private static function EncodeAsn1Integer(string $bytes): string
	{
		// Remove leading zero bytes, but ensure the high bit is not set (add 0x00 if needed)
		$bytes = ltrim($bytes, "\x00");
		if (strlen($bytes) === 0)
		{
			$bytes = "\x00";
		}
		elseif (ord($bytes[0]) > 0x7f)
		{
			$bytes = "\x00" . $bytes;
		}

		return "\x02" . self::Asn1Length($bytes) . $bytes;
	}

	private static function Asn1Length(string $content): string
	{
		$len = strlen($content);
		if ($len < 128)
		{
			return chr($len);
		}
		elseif ($len < 256)
		{
			return "\x81" . chr($len);
		}
		else
		{
			return "\x82" . chr($len >> 8) . chr($len & 0xff);
		}
	}

	// --- Base64URL helpers ---

	public static function Base64UrlDecode(string $data): string
	{
		$remainder = strlen($data) % 4;
		if ($remainder !== 0)
		{
			$data .= str_repeat('=', 4 - $remainder);
		}

		return base64_decode(strtr($data, '-_', '+/'));
	}

	public static function Base64UrlEncode(string $data): string
	{
		return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
	}
}
