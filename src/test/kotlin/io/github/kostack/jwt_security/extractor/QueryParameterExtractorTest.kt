package io.github.kostack.jwt_security.extractor

import io.github.kostack.jwt_security.configuration.JwtProperties
import org.springframework.mock.http.server.reactive.MockServerHttpRequest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class QueryParameterExtractorTest {
  @Test
  fun `extract returns token from configured query parameter`() {
    val extractor = QueryParameterExtractor(jwtProperties())
    val request =
      MockServerHttpRequest
        .get("/api?bearer=token-value")
        .build()

    assertEquals("token-value", extractor.extract(request))
  }

  @Test
  fun `extract returns null when query parameter extraction is disabled`() {
    val extractor =
      QueryParameterExtractor(
        jwtProperties(
          enabled = false
        )
      )
    val request =
      MockServerHttpRequest
        .get("/api?bearer=token-value")
        .build()

    assertNull(extractor.extract(request))
  }

  @Test
  fun `extract returns null when configured query parameter is missing`() {
    val extractor = QueryParameterExtractor(jwtProperties())
    val request =
      MockServerHttpRequest
        .get("/api?token=token-value")
        .build()

    assertNull(extractor.extract(request))
  }

  @Test
  fun `extract uses configured query parameter name`() {
    val extractor =
      QueryParameterExtractor(
        jwtProperties(
          name = "access_token"
        )
      )
    val request =
      MockServerHttpRequest
        .get("/api?access_token=token-value")
        .build()

    assertEquals("token-value", extractor.extract(request))
  }

  private fun jwtProperties(
    enabled: Boolean = true,
    name: String = "bearer"
  ): JwtProperties =
    JwtProperties(
      queryParameterOptions =
        JwtProperties.QueryParameterOptions(
          enabled = enabled,
          name = name
        )
    )
}
