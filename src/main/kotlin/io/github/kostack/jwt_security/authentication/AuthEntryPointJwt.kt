package io.github.kostack.jwt_security.authentication

import io.github.kostack.jwt_security.dto.Unauthorized
import kotlinx.serialization.json.Json
import org.slf4j.LoggerFactory
import org.springframework.core.io.buffer.DataBuffer
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.http.server.reactive.ServerHttpResponse
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.server.ServerAuthenticationEntryPoint
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import java.nio.charset.StandardCharsets

class AuthEntryPointJwt : ServerAuthenticationEntryPoint {
  override fun commence(
    exchange: ServerWebExchange,
    ex: AuthenticationException
  ): Mono<Void> {
    val response: ServerHttpResponse = exchange.response
    response.statusCode = HttpStatus.UNAUTHORIZED
    response.headers.contentType = MediaType.APPLICATION_JSON

    val body =
      Unauthorized(
        status = HttpStatus.UNAUTHORIZED.value(),
        message = "Authentication token was either missing or invalid.",
        path = exchange.request.path.value()
      )

    log.debug(
      "Unauthorized error: {}. Path: {}",
      ex.message,
      exchange.request.path.value()
    )

    return try {
      val responseBytes = Json.encodeToString(body).toByteArray()
      val buffer: DataBuffer = response.bufferFactory().wrap(responseBytes)
      response.writeWith(Mono.just(buffer))
    } catch (e: Exception) {
      log.error("Error writing JSON response: {}", e.message)
      val fallback =
        response
          .bufferFactory()
          .wrap("Unauthorized".toByteArray(StandardCharsets.UTF_8))
      response.writeWith(Mono.just(fallback))
    }
  }

  companion object {
    private val log = LoggerFactory.getLogger(AuthEntryPointJwt::class.java)
  }
}
