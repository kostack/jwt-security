package io.github.kostack.jwt_security.service

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import org.reactivestreams.Publisher
import org.springframework.core.io.buffer.DataBuffer
import org.springframework.http.HttpMethod
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.http.server.reactive.ServerHttpResponseDecorator
import org.springframework.mock.http.server.reactive.MockServerHttpRequest
import org.springframework.mock.http.server.reactive.MockServerHttpResponse
import org.springframework.mock.web.server.MockServerWebExchange
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.InsufficientAuthenticationException
import reactor.core.publisher.Mono
import java.net.URI
import java.nio.charset.StandardCharsets
import java.time.Duration

class AuthEntryPointJwtTest {
  private val entryPoint = AuthEntryPointJwt()
  private val timeout = Duration.ofSeconds(5)

  @Test
  fun `returns unauthorized JSON including default fields for missing authentication`() {
    val exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/api/private"))

    entryPoint.commence(exchange, InsufficientAuthenticationException("Authentication required")).block(timeout)

    assertThat(exchange.response.statusCode).isEqualTo(HttpStatus.UNAUTHORIZED)
    assertThat(exchange.response.headers.contentType).isEqualTo(MediaType.APPLICATION_JSON)
    val body = Json.parseToJsonElement(exchange.response.bodyAsString.block(timeout)!!).jsonObject
    assertThat(body.keys).containsExactlyInAnyOrder("status", "error", "message", "path")
    assertThat(body.getValue("status").jsonPrimitive.content).isEqualTo("401")
    assertThat(body.getValue("error").jsonPrimitive.content).isEqualTo("Unauthorized")
    assertThat(body.getValue("message").jsonPrimitive.content)
      .isEqualTo("Authentication token was either missing or invalid.")
    assertThat(body.getValue("path").jsonPrimitive.content).isEqualTo("/api/private")
  }

  @Test
  fun `excludes the query token and exception details from the response`() {
    val exchange =
      MockServerWebExchange.from(MockServerHttpRequest.get("/api/private?token=secret-token"))

    entryPoint.commence(exchange, BadCredentialsException("Signature failed for secret-token")).block(timeout)

    val response = exchange.response.bodyAsString.block(timeout)!!
    assertThat(exchange.response.statusCode).isEqualTo(HttpStatus.UNAUTHORIZED)
    assertThat(response).doesNotContain("secret-token", "Signature failed", "?token=")
    assertThat(
      Json
        .parseToJsonElement(response)
        .jsonObject
        .getValue("path")
        .jsonPrimitive.content
    ).isEqualTo("/api/private")
  }

  @ParameterizedTest
  @ValueSource(
    strings = ["/", "/api/nested/resource", "/api/%22quoted%22", "/api/%CE%B4%CE%BF%CE%BA%CE%B9%CE%BC%CE%AE"]
  )
  fun `preserves the request path in valid JSON`(path: String) {
    val exchange = MockServerWebExchange.from(MockServerHttpRequest.method(HttpMethod.GET, URI.create(path)))

    entryPoint.commence(exchange, BadCredentialsException("Invalid token")).block(timeout)

    val body = Json.parseToJsonElement(exchange.response.bodyAsString.block(timeout)!!).jsonObject
    assertThat(body.getValue("path").jsonPrimitive.content).isEqualTo(path)
  }

  @Test
  fun `uses a plain text fallback when writing JSON throws synchronously`() {
    val response = MockServerHttpResponse()
    val decoratedResponse =
      object : ServerHttpResponseDecorator(response) {
        private var firstWrite = true

        override fun writeWith(body: Publisher<out DataBuffer>): Mono<Void> {
          if (firstWrite) {
            firstWrite = false
            throw IllegalStateException("Cannot write JSON")
          }
          return super.writeWith(body)
        }
      }
    val exchange =
      MockServerWebExchange
        .from(MockServerHttpRequest.get("/api/private"))
        .mutate()
        .response(decoratedResponse)
        .build()

    entryPoint.commence(exchange, BadCredentialsException("Invalid token")).block(timeout)

    assertThat(response.statusCode).isEqualTo(HttpStatus.UNAUTHORIZED)
    assertThat(response.headers.contentType).isEqualTo(MediaType("text", "plain", StandardCharsets.UTF_8))
    assertThat(response.bodyAsString.block(timeout)).isEqualTo("Unauthorized")
  }

  @Test
  fun `propagates an asynchronous response write failure`() {
    val failure = IllegalStateException("Connection closed")
    val response = MockServerHttpResponse()
    response.setWriteHandler { Mono.error(failure) }
    val exchange =
      MockServerWebExchange
        .from(MockServerHttpRequest.get("/api/private"))
        .mutate()
        .response(response)
        .build()

    val result = entryPoint.commence(exchange, BadCredentialsException("Invalid token"))

    assertThatThrownBy { result.block(timeout) }.isSameAs(failure)
  }
}
