package io.github.kostack.jwt_security.converter

import io.github.kostack.jwt_security.autoconfigure.SecurityProperties
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import org.springframework.mock.http.server.reactive.MockServerHttpRequest
import org.springframework.mock.web.server.MockServerWebExchange
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken
import java.time.Duration

class HeaderOrQueryTokenAuthenticationConverterTest {
  @Test
  fun `extracts a standard bearer token`() {
    val request = MockServerHttpRequest.get("/api").header("Authorization", "Bearer header-token")

    assertToken(convert(request), "header-token")
  }

  @ParameterizedTest
  @ValueSource(strings = ["bearer", "BEARER", "bEaReR"])
  fun `matches the header prefix ignoring case`(prefix: String) {
    val request = MockServerHttpRequest.get("/api").header("Authorization", "$prefix header-token")

    assertToken(convert(request), "header-token")
  }

  @Test
  fun `extracts a raw token from a custom header`() {
    val properties =
      SecurityProperties(
        authorizationHeader = SecurityProperties.AuthorizationHeader(name = "x-auth", prefix = "")
      )
    val request = MockServerHttpRequest.get("/api").header("X-Auth", "header-token")

    assertToken(convert(request, properties), "header-token")
  }

  @Test
  fun `normalizes a custom prefix and trims its configuration`() {
    val properties =
      SecurityProperties(
        authorizationHeader = SecurityProperties.AuthorizationHeader(name = "x-auth", prefix = " Token ")
      )
    val request = MockServerHttpRequest.get("/api").header("x-auth", "tOkEn header-token")

    assertToken(convert(request, properties), "header-token")
  }

  @Test
  fun `does not read the default header when a custom header is configured`() {
    val properties =
      SecurityProperties(
        authorizationHeader = SecurityProperties.AuthorizationHeader(name = "x-auth")
      )
    val request = MockServerHttpRequest.get("/api").header("Authorization", "Bearer header-token")

    assertThat(convert(request, properties)).isNull()
  }

  @Test
  fun `returns empty when no token is present`() {
    assertThat(convert(MockServerHttpRequest.get("/api"))).isNull()
  }

  @Test
  fun `ignores an unrelated authorization scheme`() {
    val request = MockServerHttpRequest.get("/api").header("Authorization", "Basic credentials")

    assertThat(convert(request)).isNull()
  }

  @Test
  fun `ignores query tokens when query extraction is disabled`() {
    val properties = queryProperties().apply { queryParameter.enabled = false }
    val request = MockServerHttpRequest.get("/api").queryParam("token", "query-token")

    assertThat(convert(request, properties)).isNull()
  }

  @Test
  fun `ignores the header when header extraction is disabled`() {
    val properties = queryProperties().apply { authorizationHeader.enabled = false }
    val request =
      MockServerHttpRequest
        .get("/api")
        .header("Authorization", "Bearer header-token")
        .queryParam("token", "query-token")

    assertToken(convert(request, properties), "query-token")
    assertThat(convert(MockServerHttpRequest.get("/api").header("Authorization", "Bearer header-token"), properties))
      .isNull()
  }

  @Test
  fun `extracts a query token when enabled`() {
    val request = MockServerHttpRequest.get("/api").queryParam("token", "query-token")

    assertToken(convert(request, queryProperties()), "query-token")
  }

  @Test
  fun `only reads the configured query parameter`() {
    val properties = queryProperties().apply { queryParameter.name = "access_token" }
    val request = MockServerHttpRequest.get("/api").queryParam("token", "query-token")

    assertThat(convert(request, properties)).isNull()
    assertToken(
      convert(MockServerHttpRequest.get("/api").queryParam("access_token", "custom-token"), properties),
      "custom-token"
    )
  }

  @Test
  fun `returns empty when the configured query parameter is missing`() {
    assertThat(convert(MockServerHttpRequest.get("/api"), queryProperties())).isNull()
  }

  @ParameterizedTest
  @ValueSource(strings = ["", " ", "   "])
  fun `ignores blank query tokens`(token: String) {
    val request = MockServerHttpRequest.get("/api").queryParam("token", token)

    assertThat(convert(request, queryProperties())).isNull()
  }

  @Test
  fun `prefers a header token over a query token`() {
    val request =
      MockServerHttpRequest
        .get("/api")
        .header("Authorization", "Bearer header-token")
        .queryParam("token", "query-token")

    assertToken(convert(request, queryProperties()), "header-token")
  }

  @Test
  fun `falls back to a query token when the header scheme does not match`() {
    val request =
      MockServerHttpRequest
        .get("/api")
        .header("Authorization", "Basic credentials")
        .queryParam("token", "query-token")

    assertToken(convert(request, queryProperties()), "query-token")
  }

  @ParameterizedTest
  @ValueSource(strings = ["Bearer", "Bearer ", "Bearertoken", "Bearer invalid token", "Bearer token!"])
  fun `rejects malformed bearer headers without falling back to a query token`(header: String) {
    val request =
      MockServerHttpRequest
        .get("/api")
        .header("Authorization", header)
        .queryParam("token", "query-token")

    assertThatThrownBy { convert(request, queryProperties()) }
      .isInstanceOfSatisfying(OAuth2AuthenticationException::class.java) { exception ->
        assertThat(exception.error.errorCode).isEqualTo("invalid_token")
      }
  }

  @Test
  fun `does not change the original request when normalizing a header`() {
    val properties =
      SecurityProperties(
        authorizationHeader = SecurityProperties.AuthorizationHeader(name = "x-auth", prefix = "")
      )
    val exchange =
      MockServerWebExchange.from(
        MockServerHttpRequest.get("/api").header("x-auth", "header-token")
      )

    val authentication =
      HeaderOrQueryTokenAuthenticationConverter(properties)
        .convert(exchange)
        .block(Duration.ofSeconds(1))

    assertToken(authentication, "header-token")
    assertThat(exchange.request.headers.getFirst("x-auth")).isEqualTo("header-token")
  }

  private fun queryProperties(): SecurityProperties =
    SecurityProperties(
      queryParameter = SecurityProperties.QueryParameter(enabled = true, name = "token")
    )

  private fun convert(
    request: MockServerHttpRequest.BaseBuilder<*>,
    properties: SecurityProperties = SecurityProperties()
  ): Authentication? =
    HeaderOrQueryTokenAuthenticationConverter(properties)
      .convert(MockServerWebExchange.from(request.build()))
      .block(Duration.ofSeconds(1))

  private fun assertToken(
    authentication: Authentication?,
    expectedToken: String
  ) {
    assertThat(authentication)
      .isInstanceOfSatisfying(BearerTokenAuthenticationToken::class.java) { token ->
        assertThat(token.token).isEqualTo(expectedToken)
        assertThat(token.isAuthenticated).isFalse()
      }
  }
}
