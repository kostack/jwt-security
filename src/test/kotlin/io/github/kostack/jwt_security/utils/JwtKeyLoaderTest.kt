package io.github.kostack.jwt_security.utils

import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.InvalidKeySpecException
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertIs

class JwtKeyLoaderTest {
  @TempDir
  lateinit var tempDir: Path

  @Test
  fun `getPrivateKey loads RSA private key from PEM file`() {
    val key = JwtKeyLoader.getPrivateKey(PRIVATE_KEY_PATH)

    assertIs<RSAPrivateKey>(key)
  }

  @Test
  fun `getPublicKey loads RSA public key from PEM file`() {
    val key = JwtKeyLoader.getPublicKey(PUBLIC_KEY_PATH)

    assertIs<RSAPublicKey>(key)
  }

  @Test
  fun `getPrivateKey throws when PEM content is invalid`() {
    val privateKey = tempDir.resolve("invalid-private.pem")
    privateKey.writeText(
      """
      -----BEGIN PRIVATE KEY-----
      invalid
      -----END PRIVATE KEY-----
      """.trimIndent()
    )

    assertFailsWith<InvalidKeySpecException> {
      JwtKeyLoader.getPrivateKey(privateKey.toString())
    }
  }

  @Test
  fun `getPublicKey throws when PEM content is invalid`() {
    val publicKey = tempDir.resolve("invalid-public.pem")
    publicKey.writeText(
      """
      -----BEGIN PUBLIC KEY-----
      invalid
      -----END PUBLIC KEY-----
      """.trimIndent()
    )

    assertFailsWith<InvalidKeySpecException> {
      JwtKeyLoader.getPublicKey(publicKey.toString())
    }
  }

  private companion object {
    const val PRIVATE_KEY_PATH = "src/testFixtures/resources/jwt/private.pem"
    const val PUBLIC_KEY_PATH = "src/testFixtures/resources/jwt/public.pem"
  }
}
