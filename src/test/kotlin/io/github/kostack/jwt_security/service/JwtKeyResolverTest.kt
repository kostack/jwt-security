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
      issuer = SecurityProperties.Issuer(privateKey = encodedPem("PRIVATE KEY", firstKey.private.encoded)),
      publicKeys =
        mapOf(
          "first" to encodedPem("PUBLIC KEY", firstKey.public.encoded),
          "second" to encodedPem("PUBLIC KEY", secondKey.public.encoded)
        )
    )
  private val resolver = JwtKeyResolver(properties)

  @Test
  fun `loads the configured RSA private key`() {
    assertThat(resolver.privateKey().encoded).isEqualTo(firstKey.private.encoded)
  }

  @Test
  fun `selects the RSA public key by key ID`() {
    assertThat(resolver.publicKey("first").encoded).isEqualTo(firstKey.public.encoded)
    assertThat(resolver.publicKey("second").encoded).isEqualTo(secondKey.public.encoded)
  }

  @Test
  fun `accepts surrounding whitespace in encoded keys`() {
    properties.issuer.privateKey = " \n${properties.issuer.privateKey}\t "
    properties.publicKeys = mapOf("first" to " \n${properties.publicKeys.getValue("first")}\t ")

    assertThat(resolver.privateKey().encoded).isEqualTo(firstKey.private.encoded)
    assertThat(resolver.publicKey("first").encoded).isEqualTo(firstKey.public.encoded)
  }

  @ParameterizedTest
  @ValueSource(strings = ["unknown", "", "FIRST", " first "])
  fun `rejects a key ID without an exact configured match`(kid: String) {
    val failure = assertFailsWith<IllegalArgumentException> { resolver.publicKey(kid) }

    assertThat(failure.message).isEqualTo("No public key found: $kid")
  }

  @Test
  fun `rejects public key lookup with an empty key map`() {
    properties.publicKeys = emptyMap()

    val failure = assertFailsWith<IllegalArgumentException> { resolver.publicKey("first") }

    assertThat(failure.message).isEqualTo("No public key found: first")
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
    properties.publicKeys = properties.publicKeys + ("first" to key)

    assertFailsWith<IllegalArgumentException> { resolver.publicKey("first") }
    assertThat(resolver.publicKey("second").encoded).isEqualTo(secondKey.public.encoded)
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
    properties.publicKeys = mapOf("first" to encodedPem("PRIVATE KEY", firstKey.private.encoded))

    assertFailsWith<IllegalArgumentException> { resolver.publicKey("first") }
  }

  @Test
  fun `reads updated key configuration on subsequent lookups`() {
    resolver.privateKey()
    resolver.publicKey("first")

    properties.issuer.privateKey = encodedPem("PRIVATE KEY", secondKey.private.encoded)
    properties.publicKeys = mapOf("first" to encodedPem("PUBLIC KEY", secondKey.public.encoded))

    assertThat(resolver.privateKey().encoded).isEqualTo(secondKey.private.encoded)
    assertThat(resolver.publicKey("first").encoded).isEqualTo(secondKey.public.encoded)
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
