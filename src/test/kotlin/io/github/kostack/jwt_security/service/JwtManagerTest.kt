package io.github.kostack.jwt_security.service

import io.github.kostack.jwt_security.autoconfigure.JwtProperties
import io.github.kostack.jwt_security.utils.IssuerKeyLocator
import io.github.kostack.jwt_security.utils.JwtKeyResolver
import io.jsonwebtoken.JwtException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class JwtManagerTest {
  @Test
  fun `generateToken creates signed token with configured issuer and user claims`() {
    val jwtManager = jwtManager()
    val user = TestJwtUser("admin-1", listOf("ROLE_ADMIN"))

    val token = jwtManager.generateToken(user)
    val claims = jwtManager.getClaims(token)

    assertEquals("local", claims.header.keyId)
    assertEquals("local", claims.payload.issuer)
    assertEquals("admin-1", claims.payload.subject)
    assertEquals("admin-1", claims.payload["username"])
    assertEquals(listOf("ROLE_ADMIN"), claims.payload["roles"])
    assertNotNull(claims.payload.issuedAt)
    assertNotNull(claims.payload.expiration)
    assertTrue(claims.payload.expiration.after(claims.payload.issuedAt))
  }

  @Test
  fun `validateJwtToken returns true for generated token`() {
    val jwtManager = jwtManager()
    val token = jwtManager.generateToken(TestJwtUser("admin-1"))

    assertTrue(jwtManager.validateJwtToken(token))
  }

  @Test
  fun `validateJwtToken returns false for invalid token`() {
    val jwtManager = jwtManager()

    assertFalse(jwtManager.validateJwtToken("invalid token"))
  }

  @Test
  fun `validateJwtToken returns false for expired token`() {
    val jwtManager = jwtManager(expiration = -1)
    val token = jwtManager.generateToken(TestJwtUser("admin-1"))

    assertFalse(jwtManager.validateJwtToken(token))
  }

  @Test
  fun `getClaims throws for invalid token`() {
    val jwtManager = jwtManager()

    assertFailsWith<JwtException> {
      jwtManager.getClaims("invalid token")
    }
  }

  private fun jwtManager(
    issuer: String = "local",
    expiration: Int = 3600,
    signatureAlgorithm: String = "RS512"
  ): JwtManager {
    val jwtProperties =
      JwtProperties(
        issuer = issuer,
        expiration = expiration,
        privateKey = PRIVATE_KEY_PATH,
        publicKeys = mapOf(issuer to PUBLIC_KEY_PATH),
        signatureAlgorithm = signatureAlgorithm
      )
    val jwtKeyResolver = JwtKeyResolver(jwtProperties)
    jwtKeyResolver.init()
    val issuerKeyLocator = IssuerKeyLocator(jwtKeyResolver)

    return JwtManager(jwtProperties, jwtKeyResolver, issuerKeyLocator)
  }

  private data class TestJwtUser(
    override val identity: String,
    val roles: List<String> = emptyList()
  ) : JwtUser {
    override fun toMap(): Map<String, Any> =
      mapOf(
        "username" to identity,
        "roles" to roles
      )
  }

  private companion object {
    const val PRIVATE_KEY_PATH = "src/testFixtures/resources/jwt/private.pem"
    const val PUBLIC_KEY_PATH = "src/testFixtures/resources/jwt/public.pem"
  }
}
