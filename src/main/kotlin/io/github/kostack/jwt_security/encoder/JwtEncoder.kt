package io.github.kostack.jwt_security.encoder

import io.github.kostack.jwt_security.dto.JwtUser
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder

interface JwtEncoder {
  /**
   * Encodes [user] with [additionalClaims].
   *
   * @param expiration token lifetime in seconds from the injected clock's current time;
   *   `null` uses the configured issuer expiration time.
   */
  suspend fun encode(
    user: JwtUser,
    additionalClaims: Map<String, Any> = emptyMap(),
    expiration: Long? = null
  ): String

  suspend fun decode(token: String): Jwt

  fun decoder(): ReactiveJwtDecoder
}
