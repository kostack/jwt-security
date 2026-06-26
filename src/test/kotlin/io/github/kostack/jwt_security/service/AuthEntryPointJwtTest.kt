package io.github.kostack.jwt_security.service

import io.github.kostack.jwt_security.authentication.AuthEntryPointJwt
import io.github.kostack.jwt_security.dto.Unauthorized
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.reactor.awaitSingle
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import org.junit.jupiter.api.Assertions.assertDoesNotThrow
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.core.io.buffer.DataBuffer
import org.springframework.core.io.buffer.DataBufferUtils
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.mock.http.server.reactive.MockServerHttpRequest
import org.springframework.mock.http.server.reactive.MockServerHttpResponse
import org.springframework.mock.web.server.MockServerWebExchange
import org.springframework.security.core.AuthenticationException
import java.nio.charset.StandardCharsets

@SpringBootTest
class AuthEntryPointJwtTest {
  @Autowired
  lateinit var entryPoint: AuthEntryPointJwt

  @Test
  fun `should return unauthorized response with correct body`() =
    runTest {
      val exchange =
        MockServerWebExchange.from(
          MockServerHttpRequest.get("/test-path")
        )

      val authException = mockk<AuthenticationException>()
      every { authException.message } returns "Test Exception Message"

      // Act
      entryPoint.commence(exchange, authException).block()

      // Assert
      val response: MockServerHttpResponse = exchange.response
      assertEquals(HttpStatus.UNAUTHORIZED, response.statusCode)
      assertEquals(MediaType.APPLICATION_JSON, response.headers.contentType)

      val bodyBuffer: DataBuffer? = response.body.blockFirst()
      assertNotNull(bodyBuffer)

      val responseBody =
        DataBufferUtils
          .join(response.body)
          .map { buffer ->
            try {
              val bytes = ByteArray(buffer.readableByteCount())
              buffer.read(bytes)
              String(bytes, StandardCharsets.UTF_8)
            } finally {
              DataBufferUtils.release(buffer)
            }
          }.awaitSingle()

      val responseMap = Json.decodeFromString<Unauthorized>(responseBody)

      assertEquals(401, responseMap.status)
      assertEquals("Unauthorized", responseMap.error)
      assertEquals("Authentication token was either missing or invalid.", responseMap.message)
      assertEquals("/test-path", responseMap.path)
    }

  @Test
  fun commence_shouldHandleExceptionWhileWritingResponse() =
    runTest {
      val exchange =
        MockServerWebExchange
          .builder(
            MockServerHttpRequest.get("/test-path")
          ).build()

      val authException = mockk<AuthenticationException>()
      every { authException.message } returns "Test Exception Message"

      assertDoesNotThrow {
        entryPoint.commence(exchange, authException).block()
      }
    }
}
