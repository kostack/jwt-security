package io.github.kostack.jwt_security.service

import io.github.kostack.jwt_security.authentication.JwtServerAuthenticationConverter
import io.github.kostack.jwt_security.extractor.TokenExtractor
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kotlinx.coroutines.reactor.awaitSingleOrNull
import kotlinx.coroutines.test.runTest
import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.web.server.ServerWebExchange
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull

class JwtServerAuthenticationConverterTest {
  @Test
  fun `should return Authentication when token is extracted`() =
    runTest {
      val tokenExtractor = mockk<TokenExtractor>()
      every { tokenExtractor.extract(any<ServerHttpRequest>()) } returns "testToken"

      val converter = JwtServerAuthenticationConverter(listOf(tokenExtractor))

      // Mocks
      val request = mockk<ServerHttpRequest>()
      val exchange = mockk<ServerWebExchange>()
      every { exchange.request } returns request

      val result: Authentication? = converter.convert(exchange).awaitSingleOrNull()

      assertIs<UsernamePasswordAuthenticationToken>(result)
      assertEquals("testToken", result.principal)
      assertEquals("testToken", result.credentials)

      verify(exactly = 1) { tokenExtractor.extract(any<ServerHttpRequest>()) }
    }

  @Test
  fun `should return null when no token is extracted`() =
    runTest {
      val tokenExtractor = mockk<TokenExtractor>()
      every { tokenExtractor.extract(any<ServerHttpRequest>()) } returns null

      val converter = JwtServerAuthenticationConverter(listOf(tokenExtractor))

      val request = mockk<ServerHttpRequest>()
      val exchange = mockk<ServerWebExchange>()
      every { exchange.request } returns request

      val result: Authentication? = converter.convert(exchange).awaitSingleOrNull()

      assertNull(result)

      verify(exactly = 1) { tokenExtractor.extract(any<ServerHttpRequest>()) }
    }

  @Test
  fun `should try all token extractors and return Authentication from first match`() =
    runTest {
      val extractor1 = mockk<TokenExtractor>()
      val extractor2 = mockk<TokenExtractor>()

      every { extractor1.extract(any<ServerHttpRequest>()) } returns null
      every { extractor2.extract(any<ServerHttpRequest>()) } returns "validToken"

      val converter = JwtServerAuthenticationConverter(listOf(extractor1, extractor2))

      val request = mockk<ServerHttpRequest>()
      val exchange = mockk<ServerWebExchange>()
      every { exchange.request } returns request

      val result: Authentication? = converter.convert(exchange).awaitSingleOrNull()

      assertIs<UsernamePasswordAuthenticationToken>(result)
      assertEquals("validToken", result.principal)
      assertEquals("validToken", result.credentials)

      verify(exactly = 1) { extractor1.extract(any<ServerHttpRequest>()) }
      verify(exactly = 1) { extractor2.extract(any<ServerHttpRequest>()) }
    }

  @Test
  fun `should return null when all extractors fail`() =
    runTest {
      val extractor1 = mockk<TokenExtractor>()
      val extractor2 = mockk<TokenExtractor>()

      every { extractor1.extract(any<ServerHttpRequest>()) } returns null
      every { extractor2.extract(any<ServerHttpRequest>()) } returns null

      val converter = JwtServerAuthenticationConverter(listOf(extractor1, extractor2))

      val request = mockk<ServerHttpRequest>()
      val exchange = mockk<ServerWebExchange>()
      every { exchange.request } returns request

      val result: Authentication? = converter.convert(exchange).awaitSingleOrNull()

      assertNull(result)

      verify(exactly = 1) { extractor1.extract(any<ServerHttpRequest>()) }
      verify(exactly = 1) { extractor2.extract(any<ServerHttpRequest>()) }
    }
}
