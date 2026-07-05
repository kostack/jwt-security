package io.github.kostack.jwt_security.utils

import io.github.kostack.jwt_security.autoconfigure.JwtProperties
import io.jsonwebtoken.JwsHeader
import io.jsonwebtoken.JwtException
import io.mockk.every
import io.mockk.mockk
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertSame

class IssuerKeyLocatorTest {
  @Test
  fun `locate returns public key for header key id`() {
    val resolver = JwtKeyResolver(jwtProperties())
    resolver.init()
    val locator = IssuerKeyLocator(resolver)
    val expectedKey = resolver.getPublicKeyBasedOnIssuer("local")

    val key = locator.locate(jwsHeader("local"))

    assertSame(expectedKey, key)
  }

  @Test
  fun `locate throws when header key id is missing`() {
    val resolver = JwtKeyResolver(jwtProperties())
    resolver.init()
    val locator = IssuerKeyLocator(resolver)

    assertFailsWith<JwtException> {
      locator.locate(jwsHeader())
    }
  }

  @Test
  fun `locate throws when header key id has no configured public key`() {
    val resolver = JwtKeyResolver(jwtProperties())
    resolver.init()
    val locator = IssuerKeyLocator(resolver)

    assertFailsWith<RuntimeException> {
      locator.locate(jwsHeader("missing"))
    }
  }

  private fun jwsHeader(keyId: String? = null): JwsHeader {
    val header = mockk<JwsHeader>()
    every { header.keyId } returns keyId
    return header
  }

  private fun jwtProperties(): JwtProperties =
    JwtProperties(
      privateKey = "src/testFixtures/resources/jwt/private.pem",
      publicKeys = mapOf("local" to "src/testFixtures/resources/jwt/public.pem")
    )
}
