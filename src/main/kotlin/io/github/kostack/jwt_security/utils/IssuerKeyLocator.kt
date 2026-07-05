package io.github.kostack.jwt_security.utils

import io.jsonwebtoken.JwsHeader
import io.jsonwebtoken.JwtException
import io.jsonwebtoken.LocatorAdapter
import java.security.Key

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
