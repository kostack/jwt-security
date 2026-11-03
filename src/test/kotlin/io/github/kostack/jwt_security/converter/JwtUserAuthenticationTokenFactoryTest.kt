package io.github.kostack.jwt_security.converter

import io.github.kostack.jwt_security.dto.JwtUser
import io.github.kostack.jwt_security.service.UserProvider
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.NullAndEmptySource
import org.junit.jupiter.params.provider.ValueSource
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken

class JwtUserAuthenticationTokenFactoryTest {
  private val userProvider = mockk<UserProvider>()
  private val factory = JwtUserAuthenticationTokenFactory(userProvider)
  private val user = mockk<JwtUser>()

  @Test
  fun `creates an authenticated token with the loaded user and delegated authorities`() =
    runTest {
      val jwt = jwt("admin")
      val authorities = listOf(SimpleGrantedAuthority("ROLE_ADMIN"), SimpleGrantedAuthority("SCOPE_read"))
      val authentication = JwtAuthenticationToken(jwt, authorities)
      coEvery { userProvider.load("admin", jwt.claims) } returns user

      val result = factory.create(jwt, authentication)

      assertThat(result.isAuthenticated).isTrue()
      assertThat(result.principal).isSameAs(user)
      assertThat(result.credentials).isNull()
      assertThat(result.authorities).containsExactlyElementsOf(authorities)
      coVerify(exactly = 1) { userProvider.load("admin", jwt.claims) }
    }

  @Test
  fun `creates an authenticated token when delegated authorities are empty`() =
    runTest {
      val jwt = jwt("admin")
      coEvery { userProvider.load("admin", jwt.claims) } returns user

      val result = factory.create(jwt, JwtAuthenticationToken(jwt))

      assertThat(result.isAuthenticated).isTrue()
      assertThat(result.principal).isSameAs(user)
      assertThat(result.authorities).isEmpty()
    }

  @ParameterizedTest
  @NullAndEmptySource
  @ValueSource(strings = [" ", "\t", "\n", "   "])
  fun `rejects a missing or blank subject without loading a user`(subject: String?) {
    val jwt = jwt(subject)

    assertThatThrownBy { runTest { factory.create(jwt, JwtAuthenticationToken(jwt)) } }
      .isInstanceOf(BadCredentialsException::class.java)
      .hasMessage("Missing subject")

    coVerify(exactly = 0) { userProvider.load(any(), any()) }
  }

  @Test
  fun `passes a nonblank subject to the provider without trimming it`() =
    runTest {
      val jwt = jwt(" admin ")
      coEvery { userProvider.load(" admin ", jwt.claims) } returns user

      val result = factory.create(jwt, JwtAuthenticationToken(jwt))

      assertThat(result.principal).isSameAs(user)
      coVerify(exactly = 1) { userProvider.load(" admin ", jwt.claims) }
    }

  @Test
  fun `rejects a subject whose user cannot be found`() {
    val jwt = jwt("unknown")
    coEvery { userProvider.load("unknown", jwt.claims) } returns null

    assertThatThrownBy { runTest { factory.create(jwt, JwtAuthenticationToken(jwt)) } }
      .isInstanceOf(BadCredentialsException::class.java)
      .hasMessage("User not found")

    coVerify(exactly = 1) { userProvider.load("unknown", jwt.claims) }
  }

  @Test
  fun `propagates a user provider failure`() {
    val jwt = jwt("admin")
    val failure = IllegalStateException("User provider unavailable")
    coEvery { userProvider.load("admin", jwt.claims) } throws failure

    assertThatThrownBy { runTest { factory.create(jwt, JwtAuthenticationToken(jwt)) } }
      .isSameAs(failure)
  }

  private fun jwt(subject: String?): Jwt =
    Jwt
      .withTokenValue("token")
      .header("alg", "RS512")
      .claim("tenant", "test-tenant")
      .claim("roles", listOf("ignored-claim-role"))
      .apply { if (subject != null) subject(subject) }
      .build()
}
