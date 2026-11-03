package io.github.kostack.jwt_security.encoder

import io.github.kostack.jwt_security.autoconfigure.SecurityProperties
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult
import org.springframework.security.oauth2.jwt.Jwt
import java.time.Instant

class RequiredJwtClaimsValidatorTest {
  private val properties = SecurityProperties(issuer = SecurityProperties.Issuer(audience = "test-api"))
  private val validator = RequiredJwtClaimsValidator(properties)

  @Test
  fun `accepts all required claims`() {
    assertSuccess(validator.validate(jwt()))
  }

  @Test
  fun `accepts the configured audience among other audiences`() {
    assertSuccess(validator.validate(jwt(mapOf("aud" to listOf("other-api", "test-api", "third-api")))))
  }

  @ParameterizedTest
  @ValueSource(strings = ["aud", "roles", "exp", "sub"])
  fun `rejects each missing required claim`(claim: String) {
    assertInvalid(validator.validate(jwt(omittedClaim = claim)))
  }

  @ParameterizedTest
  @ValueSource(strings = ["other-api", "test-api-extra", "TEST-API", ""])
  fun `rejects an audience without an exact match`(audience: String) {
    assertInvalid(validator.validate(jwt(mapOf("aud" to listOf(audience)))))
  }

  @Test
  fun `rejects an empty audience list`() {
    assertInvalid(validator.validate(jwt(mapOf("aud" to emptyList<String>()))))
  }

  @ParameterizedTest
  @ValueSource(strings = ["", " ", "\t", "\n", " \t\n"])
  fun `rejects a blank subject`(subject: String) {
    assertInvalid(validator.validate(jwt(mapOf("sub" to subject))))
  }

  @Test
  fun `accepts an empty authorities list`() {
    assertSuccess(validator.validate(jwt(mapOf("roles" to emptyList<String>()))))
  }

  @Test
  fun `accepts the configured authorities claim instead of the default`() {
    properties.authoritiesClaim = "permissions"

    assertSuccess(validator.validate(jwt(mapOf("permissions" to listOf("read")), omittedClaim = "roles")))
  }

  @Test
  fun `rejects the default authorities claim when a different claim is configured`() {
    properties.authoritiesClaim = "permissions"

    assertInvalid(validator.validate(jwt()))
  }

  @Test
  fun `leaves issuer validation to the issuer validator`() {
    assertSuccess(validator.validate(jwt(mapOf("iss" to "https://other.test"))))
  }

  @Test
  fun `leaves expiration time validation to the timestamp validator`() {
    assertSuccess(validator.validate(jwt(mapOf("exp" to Instant.EPOCH))))
  }

  @Test
  fun `returns one error when multiple required claims are missing`() {
    val jwt =
      Jwt
        .withTokenValue("token")
        .header("alg", "RS512")
        .claim("unrelated", "value")
        .build()

    assertInvalid(validator.validate(jwt))
  }

  private fun assertSuccess(result: OAuth2TokenValidatorResult) {
    assertThat(result.hasErrors()).isFalse()
    assertThat(result.errors).isEmpty()
  }

  private fun assertInvalid(result: OAuth2TokenValidatorResult) {
    assertThat(result.hasErrors()).isTrue()
    assertThat(result.errors).hasSize(1)
    val error = result.errors.single()
    assertThat(error.errorCode).isEqualTo("invalid_token")
    assertThat(error.description).isEqualTo("Required claims are missing or invalid")
    assertThat(error.uri).isNull()
  }

  private fun jwt(
    overrides: Map<String, Any> = emptyMap(),
    omittedClaim: String? = null
  ): Jwt {
    val claims =
      mapOf(
        "aud" to listOf("test-api"),
        "roles" to listOf("ROLE_USER"),
        "exp" to Instant.parse("2100-01-01T00:00:00Z"),
        "sub" to "user-123"
      ) + overrides
    return Jwt
      .withTokenValue("token")
      .header("alg", "RS512")
      .claims { it.putAll(claims.filterKeys { name -> name != omittedClaim }) }
      .build()
  }
}
