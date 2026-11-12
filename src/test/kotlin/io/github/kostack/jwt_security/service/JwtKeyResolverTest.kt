package io.github.kostack.jwt_security.service

import io.github.kostack.jwt_security.autoconfigure.SecurityProperties
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import java.security.KeyPairGenerator
import java.util.Base64
import kotlin.test.assertFailsWith

class JwtKeyResolverTest {
  private val properties =
    SecurityProperties(
      issuer =
        SecurityProperties.Issuer(
          kid = "https://issuer.local",
          privateKey = encodedPem("PRIVATE KEY", firstKey.private.encoded)
        ),
      trustedIssuers =
        mapOf(
          "local" to
            SecurityProperties.TrustedIssuer(
              issuer = "https://issuer.local",
              publicKey = encodedPem("PUBLIC KEY", firstKey.public.encoded)
            ),
          "second" to
            SecurityProperties.TrustedIssuer(
              issuer = "https://second.test",
              publicKey = encodedPem("PUBLIC KEY", secondKey.public.encoded)
            )
        )
    )
  private val resolver = JwtKeyResolver(properties)
  private val trustedIssuer get() = properties.trustedIssuers.getValue("local")

  @Test
  fun `loads the configured RSA private key`() {
    assertThat(resolver.privateKey().encoded).isEqualTo(firstKey.private.encoded)
  }

  @Test
  fun `selects the single RSA public key for each issuer`() {
    assertThat(resolver.publicKey("https://issuer.local").encoded).isEqualTo(firstKey.public.encoded)
    assertThat(
      resolver.publicKey("https://second.test").encoded
    ).isEqualTo(secondKey.public.encoded)
  }

  @Test
  fun `selects keys by issuer only`() {
    properties.trustedIssuers = properties.trustedIssuers + (
      "other" to
        SecurityProperties.TrustedIssuer(
          issuer = "https://other.test",
          publicKey = encodedPem("PUBLIC KEY", secondKey.public.encoded)
        )
    )
    assertThat(resolver.publicKey("https://issuer.local").encoded).isEqualTo(firstKey.public.encoded)
    assertThat(resolver.publicKey("https://other.test").encoded)
      .isEqualTo(secondKey.public.encoded)
    assertFailsWith<IllegalArgumentException> { resolver.publicKey("https://unknown.test") }
  }

  @Test
  fun `accepts surrounding whitespace in encoded keys`() {
    properties.issuer.privateKey = " \n${properties.issuer.privateKey}\t "
    trustedIssuer.publicKey = " \n${trustedIssuer.publicKey}\t "

    assertThat(resolver.privateKey().encoded).isEqualTo(firstKey.private.encoded)
    assertThat(resolver.publicKey("https://issuer.local").encoded).isEqualTo(firstKey.public.encoded)
  }

  @ParameterizedTest
  @ValueSource(strings = ["unknown", "", "HTTPS://ISSUER.LOCAL", " https://issuer.local "])
  fun `rejects an issuer without an exact configured match`(issuer: String) {
    val failure = assertFailsWith<IllegalArgumentException> { resolver.publicKey(issuer) }

    assertThat(failure.message).isEqualTo("No public key found: $issuer")
  }

  @Test
  fun `rejects public key lookup without a configured key`() {
    trustedIssuer.publicKey = ""

    val failure = assertFailsWith<IllegalArgumentException> { resolver.publicKey("https://issuer.local") }

    assertThat(failure.message).isEqualTo("No public key found: https://issuer.local")
  }

  @ParameterizedTest
  @ValueSource(strings = ["", " ", "invalid-base64!", "bm90IGEgUEVNIGtleQ=="])
  fun `wraps malformed private keys and preserves the parsing cause`(key: String) {
    properties.issuer.privateKey = key

    val failure = assertFailsWith<IllegalStateException> { resolver.privateKey() }

    assertThat(failure.message).isEqualTo("Invalid private key")
    assertThat(failure.cause).isInstanceOf(IllegalArgumentException::class.java)
  }

  @ParameterizedTest
  @ValueSource(strings = ["", " ", "invalid-base64!", "bm90IGEgUEVNIGtleQ=="])
  fun `rejects malformed public keys without falling back to another key`(key: String) {
    trustedIssuer.publicKey = key

    assertFailsWith<IllegalArgumentException> { resolver.publicKey("https://issuer.local") }
    assertThat(
      resolver.publicKey("https://second.test").encoded
    ).isEqualTo(secondKey.public.encoded)
  }

  @Test
  fun `rejects a public key configured as the private key`() {
    properties.issuer.privateKey = encodedPem("PUBLIC KEY", firstKey.public.encoded)

    val failure = assertFailsWith<IllegalStateException> { resolver.privateKey() }

    assertThat(failure.message).isEqualTo("Invalid private key")
    assertThat(failure.cause).isInstanceOf(IllegalArgumentException::class.java)
  }

  @Test
  fun `rejects a private key configured as a public key`() {
    trustedIssuer.publicKey = encodedPem("PRIVATE KEY", firstKey.private.encoded)

    assertFailsWith<IllegalArgumentException> { resolver.publicKey("https://issuer.local") }
  }

  @Test
  fun `reads updated key configuration on subsequent lookups`() {
    resolver.privateKey()
    resolver.publicKey("https://issuer.local")

    properties.issuer.privateKey = encodedPem("PRIVATE KEY", secondKey.private.encoded)
    trustedIssuer.publicKey = encodedPem("PUBLIC KEY", secondKey.public.encoded)

    assertThat(resolver.privateKey().encoded).isEqualTo(secondKey.private.encoded)
    assertThat(resolver.publicKey("https://issuer.local").encoded).isEqualTo(secondKey.public.encoded)
    assertFailsWith<IllegalArgumentException> { resolver.publicKey("second") }
  }

  companion object {
    private val firstKey by lazy { KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair() }
    private val secondKey by lazy { KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair() }

    private fun encodedPem(
      label: String,
      encoded: ByteArray
    ): String {
      val body = Base64.getMimeEncoder(64, byteArrayOf(10)).encodeToString(encoded)
      val pem = "-----BEGIN $label-----\n$body\n-----END $label-----\n"
      return Base64.getEncoder().encodeToString(pem.toByteArray(Charsets.UTF_8))
    }
  }
}
