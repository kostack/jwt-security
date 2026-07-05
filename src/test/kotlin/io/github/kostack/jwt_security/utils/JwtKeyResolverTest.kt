package io.github.kostack.jwt_security.utils

import io.github.kostack.jwt_security.autoconfigure.JwtProperties
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull

class JwtKeyResolverTest {
  @Test
  fun `init loads configured private and public keys`() {
    val resolver = JwtKeyResolver(jwtProperties())

    resolver.init()

    assertIs<RSAPrivateKey>(resolver.privateKey)
    assertIs<RSAPublicKey>(resolver.getPublicKeyBasedOnIssuer("local"))
  }

  @Test
  fun `getPublicKeyBasedOnIssuer throws when issuer is unknown`() {
    val resolver = JwtKeyResolver(jwtProperties())
    resolver.init()

    assertFailsWith<RuntimeException> {
      resolver.getPublicKeyBasedOnIssuer("missing")
    }
  }

  @Test
  fun `init keeps private key null when configured private key cannot be loaded`() {
    val resolver =
      JwtKeyResolver(
        jwtProperties(
          privateKey = "src/testFixtures/resources/jwt/missing-private.pem"
        )
      )

    resolver.init()

    assertNull(resolver.privateKey)
    assertFailsWith<RuntimeException> {
      resolver.getPublicKeyBasedOnIssuer("missing")
    }
  }

  private fun jwtProperties(
    privateKey: String = PRIVATE_KEY_PATH,
    publicKeys: Map<String, String> = mapOf("local" to PUBLIC_KEY_PATH)
  ): JwtProperties =
    JwtProperties(
      privateKey = privateKey,
      publicKeys = publicKeys
    )

  private companion object {
    const val PRIVATE_KEY_PATH = "src/testFixtures/resources/jwt/private.pem"
    const val PUBLIC_KEY_PATH = "src/testFixtures/resources/jwt/public.pem"
  }
}
