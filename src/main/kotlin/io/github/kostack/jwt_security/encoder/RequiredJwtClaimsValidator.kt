package io.github.kostack.jwt_security.encoder

import io.github.kostack.jwt_security.autoconfigure.SecurityProperties
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult
import org.springframework.security.oauth2.jwt.Jwt

class RequiredJwtClaimsValidator(
  private val properties: SecurityProperties
) : JwtClaimsValidator {
  override fun validate(jwt: Jwt): OAuth2TokenValidatorResult {
    val audience =
      properties.trustedIssuers.values
        .firstOrNull { it.issuer == jwt.getClaimAsString("iss") }
        ?.audience
        ?: properties.issuer.audience
    return if (jwt.audience?.contains(audience) == true &&
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
}
