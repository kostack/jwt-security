package io.github.kostack.jwt_security.encoder

import io.github.kostack.jwt_security.autoconfigure.SecurityProperties
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult
import org.springframework.security.oauth2.jwt.Jwt

class RequiredJwtClaimsValidator(
  private val properties: SecurityProperties
) : JwtClaimsValidator {
  override fun validate(jwt: Jwt): OAuth2TokenValidatorResult =
    if (jwt.audience?.contains(properties.issuer.audience) == true &&
      jwt.claims.containsKey(properties.authoritiesClaim) &&
      jwt.expiresAt != null &&
      !jwt.subject.isNullOrBlank()
    ) {
      OAuth2TokenValidatorResult.success()
    } else {
      OAuth2TokenValidatorResult.failure(
        OAuth2Error(
          "invalid_token",
          "Required claims are missing or invalid",
          null
        )
      )
    }
}
