package io.github.kostack.jwt_security.extractor

import io.github.kostack.jwt_security.autoconfigure.JwtProperties
import org.springframework.mock.http.server.reactive.MockServerHttpRequest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class HeaderExtractorTest {
  @Test
  fun `extract returns bearer token from configured header`() {
    val extractor = HeaderExtractor(jwtProperties())
    val request =
      MockServerHttpRequest
        .get("/api")
        .header("Authorization", "Bearer token-value")
        .build()

    assertEquals("token-value", extractor.extract(request))
  }

  @Test
  fun `extract returns null when authorization header extraction is disabled`() {
    val extractor =
      HeaderExtractor(
        jwtProperties(
          enabled = false
        )
      )
    val request =
      MockServerHttpRequest
        .get("/api")
        .header("Authorization", "Bearer token-value")
        .build()

    assertNull(extractor.extract(request))
  }

  @Test
  fun `extract returns null when configured header is missing`() {
    val extractor = HeaderExtractor(jwtProperties())
    val request = MockServerHttpRequest.get("/api").build()

    assertNull(extractor.extract(request))
  }

  @Test
  fun `extract returns null when header does not start with configured prefix`() {
    val extractor = HeaderExtractor(jwtProperties())
    val request =
      MockServerHttpRequest
        .get("/api")
        .header("Authorization", "Basic token-value")
        .build()

    assertNull(extractor.extract(request))
  }

  @Test
  fun `extract uses configured header name and prefix`() {
    val extractor =
      HeaderExtractor(
        jwtProperties(
          name = "X-Auth-Token",
          prefix = "Token"
        )
      )
    val request =
      MockServerHttpRequest
        .get("/api")
        .header("X-Auth-Token", "Token token-value")
        .build()

    assertEquals("token-value", extractor.extract(request))
  }

  private fun jwtProperties(
    enabled: Boolean = true,
    name: String = "Authorization",
    prefix: String = "Bearer"
  ): JwtProperties =
    JwtProperties(
      authorizationHeaderOptions =
        JwtProperties.AuthorizationHeaderOptions(
          enabled = enabled,
          name = name,
          prefix = prefix
        )
    )
}
