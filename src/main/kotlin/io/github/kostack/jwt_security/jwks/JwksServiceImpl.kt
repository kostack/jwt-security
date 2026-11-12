package io.github.kostack.jwt_security.jwks

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import io.github.kostack.jwt_security.autoconfigure.SecurityProperties
import io.github.kostack.jwt_security.service.JwtKeyResolver

internal class JwksServiceImpl(
  private val properties: SecurityProperties,
  private val keyResolver: JwtKeyResolver
) : JwksService {
  override fun publicKeys(): Map<String, Any> =
    JWKSet(
      properties.trustedIssuers.values.filter { it.publicKey.isNotBlank() }.map { issuer ->
        RSAKey
          .Builder(keyResolver.publicKey(issuer.issuer))
          .keyID(issuer.issuer)
          .keyUse(KeyUse.SIGNATURE)
          .algorithm(JWSAlgorithm.parse(issuer.algorithm.name))
          .build()
      }
    ).toJSONObject()
}
