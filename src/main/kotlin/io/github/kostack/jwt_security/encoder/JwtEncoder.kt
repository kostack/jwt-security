package io.github.kostack.jwt_security.encoder

import io.github.kostack.jwt_security.dto.JwtUser
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder
import java.time.Instant

interface JwtEncoder {
  /**
   * Encodes [user] with an absolute expiry [expiresAt], overriding any supplied `exp` claim.
   * Omitting [expiresAt] or passing `null` uses the current injected clock time plus
   * the configured issuer expiration time in seconds.
   */
  suspend fun encode(
    user: JwtUser,
    additionalClaims: Map<String, Any> = emptyMap(),
    expiresAt: Instant? = null
  ): String

  suspend fun decode(token: String): Jwt

  fun decoder(): ReactiveJwtDecoder
}
