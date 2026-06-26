package io.github.kostack.jwt_security.service

import com.ninjasquad.springmockk.MockkBean
import io.github.kostack.jwt_security.authentication.TokenAuthenticationManager
import io.github.kostack.jwt_security.model.User
import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jws
import io.mockk.Called
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.confirmVerified
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kotlinx.coroutines.reactor.awaitSingleOrNull
import kotlinx.coroutines.test.runTest
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

@SpringBootTest
class TokenAuthenticationManagerTest {
  @MockkBean
  lateinit var jwtManager: JwtManager

  @MockkBean
  lateinit var userService: JwtUserService

  @Autowired
  lateinit var authenticationManager: TokenAuthenticationManager

  @Test
  fun `authenticate valid token returns authenticated token`() =
    runTest {
      val token = "validToken"

      val claims = mockk<Jws<Claims>>()
      val payload = mockk<Claims>()

      every { claims.payload } returns payload
      every { payload.subject } returns "testUser"
      every { payload["roles"] } returns listOf("ROLE_USER")

      every { jwtManager.validateJwtToken(token) } returns true
      every { jwtManager.getClaims(token) } returns claims

      coEvery { userService.upsertFromPayload(payload) } returns
        User("1", "testUser", listOf("ROLE_USER"))

      val authentication = UsernamePasswordAuthenticationToken(null, token)

      val authenticatedToken = authenticationManager.authenticate(authentication).awaitSingleOrNull()

      assertNotNull(authenticatedToken)
      val user = authenticatedToken.principal as JwtUser
      assertEquals("testUser", user.identity)
      assertEquals(1, authenticatedToken.authorities.size)
      assertTrue(authenticatedToken.authorities.any { it.authority == "ROLE_USER" })

      verify(exactly = 1) { jwtManager.validateJwtToken(token) }
      verify(exactly = 1) { jwtManager.getClaims(token) }
      coVerify(exactly = 1) { userService.upsertFromPayload(payload) }
      confirmVerified(jwtManager, userService)
    }

  @Test
  fun `authenticate invalid token throws BadCredentialsException`() =
    runTest {
      val token = "invalidToken"
      every { jwtManager.validateJwtToken(token) } returns false

      val authentication = UsernamePasswordAuthenticationToken(null, token)

      val exception =
        assertFailsWith<BadCredentialsException> {
          authenticationManager.authenticate(authentication).awaitSingleOrNull()
        }

      assertEquals("Invalid token", exception.message)
      verify(exactly = 1) { jwtManager.validateJwtToken(token) }
      verify(exactly = 0) { userService wasNot Called }
    }

  @Test
  fun `authenticate missing username throws BadCredentialsException`() =
    runTest {
      val token = "tokenWithoutUsername"

      val claims = mockk<Jws<Claims>>()
      val payload = mockk<Claims>()

      every { claims.payload } returns payload
      every { payload.subject } returns null

      every { jwtManager.validateJwtToken(token) } returns true
      every { jwtManager.getClaims(token) } returns claims

      val authentication = UsernamePasswordAuthenticationToken(null, token)

      val exception =
        assertFailsWith<BadCredentialsException> {
          authenticationManager.authenticate(authentication).awaitSingleOrNull()
        }

      assertEquals("Invalid token payload", exception.message)

      verify(exactly = 1) { jwtManager.validateJwtToken(token) }
      verify(exactly = 1) { jwtManager.getClaims(token) }
      verify(exactly = 0) { userService wasNot Called }
    }

  @Test
  fun `authenticate invalid roles format throws Exception`() =
    runTest {
      val token = "tokenWithInvalidRoles"

      val claims = mockk<Jws<Claims>>()
      val payload = mockk<Claims>()

      every { claims.payload } returns payload
      every { payload.subject } returns "testUser"
      every { payload["roles"] } returns "notAList"

      every { jwtManager.validateJwtToken(token) } returns true
      every { jwtManager.getClaims(token) } returns claims

      val authentication = UsernamePasswordAuthenticationToken(null, token)

      val exception =
        assertFailsWith<BadCredentialsException> {
          authenticationManager.authenticate(authentication).awaitSingleOrNull()
        }

      assertEquals("Error during authentication", exception.message)

      verify(exactly = 1) { jwtManager.validateJwtToken(token) }
      verify(exactly = 1) { jwtManager.getClaims(token) }
      verify(exactly = 0) { userService wasNot Called }
    }

  @Test
  fun `authenticate exception during authentication throws Exception`() =
    runTest {
      val token = "errorToken"
      every { jwtManager.validateJwtToken(token) } throws RuntimeException("Unexpected error")

      val authentication = UsernamePasswordAuthenticationToken(null, token)

      val exception =
        assertFailsWith<BadCredentialsException> {
          authenticationManager.authenticate(authentication).awaitSingleOrNull()
        }

      assertEquals("Error during authentication", exception.message)

      verify(exactly = 1) { jwtManager.validateJwtToken(token) }
      verify(exactly = 0) { userService wasNot Called }
    }
}
