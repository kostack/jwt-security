package io.github.kostack.jwt_security.converter

import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kotlinx.coroutines.CompletableDeferred
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter
import reactor.core.publisher.Mono
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit

// MockK records Publisher-returning calls in every/verify without subscribing to them.
@Suppress("ReactiveStreamsUnusedPublisher")
class JwtAuthenticationConverterTest {
  private val tokenFactory = mockk<JwtAuthenticationTokenFactory>()
  private val delegate = mockk<ReactiveJwtAuthenticationConverter>()
  private val converter = JwtAuthenticationConverter(tokenFactory, delegate)
  private val jwt =
    Jwt
      .withTokenValue("token")
      .header("alg", "RS512")
      .subject("admin")
      .build()
  private val authorities = listOf(SimpleGrantedAuthority("ROLE_ADMIN"))
  private val delegatedAuthentication = JwtAuthenticationToken(jwt, authorities)
  private val authentication = UsernamePasswordAuthenticationToken.authenticated("admin", null, authorities)
  private val timeout = Duration.ofSeconds(5)

  @Test
  fun `passes the JWT and delegated authentication to the factory and returns its token`() {
    every { delegate.convert(jwt) } returns Mono.just(delegatedAuthentication)
    coEvery { tokenFactory.create(jwt, delegatedAuthentication) } returns authentication

    val result = converter.convert(jwt).block(timeout)

    assertThat(result).isSameAs(authentication)
    verify(exactly = 1) { delegate.convert(jwt) }
    coVerify(exactly = 1) { tokenFactory.create(jwt, delegatedAuthentication) }
  }

  @Test
  fun `returns empty without invoking the factory when the delegate returns empty`() {
    every { delegate.convert(jwt) } returns Mono.empty()

    assertThat(converter.convert(jwt).block(timeout)).isNull()

    coVerify(exactly = 0) { tokenFactory.create(any(), any()) }
  }

  @Test
  fun `propagates a delegate error without invoking the factory`() {
    val failure = BadCredentialsException("Invalid delegated authentication")
    every { delegate.convert(jwt) } returns Mono.error(failure)

    assertThatThrownBy { converter.convert(jwt).block(timeout) }.isSameAs(failure)

    coVerify(exactly = 0) { tokenFactory.create(any(), any()) }
  }

  @Test
  fun `propagates a synchronous delegate failure through the publisher`() {
    val failure = IllegalStateException("Delegate failed")
    every { delegate.convert(jwt) } throws failure

    val publisher = converter.convert(jwt)

    assertThatThrownBy { publisher.block(timeout) }.isSameAs(failure)
    coVerify(exactly = 0) { tokenFactory.create(any(), any()) }
  }

  @Test
  fun `propagates a factory authentication error`() {
    val failure = BadCredentialsException("User not found")
    every { delegate.convert(jwt) } returns Mono.just(delegatedAuthentication)
    coEvery { tokenFactory.create(jwt, delegatedAuthentication) } throws failure

    assertThatThrownBy { converter.convert(jwt).block(timeout) }.isSameAs(failure)

    coVerify(exactly = 1) { tokenFactory.create(jwt, delegatedAuthentication) }
  }

  @Test
  fun `defers authentication until subscription and repeats it for each subscriber`() {
    every { delegate.convert(jwt) } returns Mono.just(delegatedAuthentication)
    coEvery { tokenFactory.create(jwt, delegatedAuthentication) } returns authentication

    val publisher = converter.convert(jwt)

    verify(exactly = 0) { delegate.convert(any()) }
    coVerify(exactly = 0) { tokenFactory.create(any(), any()) }

    assertThat(publisher.block(timeout)).isSameAs(authentication)
    assertThat(publisher.block(timeout)).isSameAs(authentication)

    verify(exactly = 2) { delegate.convert(jwt) }
    coVerify(exactly = 2) { tokenFactory.create(jwt, delegatedAuthentication) }
  }

  @Test
  fun `waits for an asynchronous delegate before invoking the factory`() {
    val delegatedResult = CompletableFuture<JwtAuthenticationToken>()
    every { delegate.convert(jwt) } returns Mono.fromFuture(delegatedResult)
    coEvery { tokenFactory.create(jwt, delegatedAuthentication) } returns authentication

    val result = converter.convert(jwt).toFuture()

    assertThat(result).isNotDone()
    coVerify(exactly = 0) { tokenFactory.create(any(), any()) }
    delegatedResult.complete(delegatedAuthentication)

    assertThat(result.get(timeout.toMillis(), TimeUnit.MILLISECONDS)).isSameAs(authentication)
    coVerify(exactly = 1) { tokenFactory.create(jwt, delegatedAuthentication) }
  }

  @Test
  fun `waits for a suspending token factory to finish`() {
    val enteredFactory = CompletableFuture<Unit>()
    val resumeFactory = CompletableDeferred<Unit>()
    every { delegate.convert(jwt) } returns Mono.just(delegatedAuthentication)
    coEvery { tokenFactory.create(jwt, delegatedAuthentication) } coAnswers {
      enteredFactory.complete(Unit)
      resumeFactory.await()
      authentication
    }

    val result = converter.convert(jwt).toFuture()

    try {
      enteredFactory.get(timeout.toMillis(), TimeUnit.MILLISECONDS)
      assertThat(result).isNotDone()
    } finally {
      resumeFactory.complete(Unit)
    }

    assertThat(result.get(timeout.toMillis(), TimeUnit.MILLISECONDS)).isSameAs(authentication)
    coVerify(exactly = 1) { tokenFactory.create(jwt, delegatedAuthentication) }
  }
}
