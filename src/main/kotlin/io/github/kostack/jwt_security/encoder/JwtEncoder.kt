package io.github.kostack.jwt_security.encoder

import io.github.kostack.jwt_security.dto.JwtUser
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder

interface JwtEncoder {
  suspend fun encode(
    user: JwtUser,
    additionalClaims: Map<String, Any> = emptyMap()
  ): String

  suspend fun decode(token: String): Jwt

  fun decoder(): ReactiveJwtDecoder
}
