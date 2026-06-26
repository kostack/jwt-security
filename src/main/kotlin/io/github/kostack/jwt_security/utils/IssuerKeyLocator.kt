package io.github.kostack.jwt_security.utils

import io.jsonwebtoken.JwsHeader
import io.jsonwebtoken.JwtException
import io.jsonwebtoken.LocatorAdapter
import org.springframework.stereotype.Component
import java.security.Key

@Component
class IssuerKeyLocator(
  private val jwtKeyResolver: JwtKeyResolver
) : LocatorAdapter<Key>() {
  override fun locate(header: JwsHeader): Key {
    val keyId =
      header.keyId
        ?: throw JwtException("JWT keyId is missing; cannot locate verification key")

    return jwtKeyResolver.getPublicKeyBasedOnIssuer(keyId)
  }
}
