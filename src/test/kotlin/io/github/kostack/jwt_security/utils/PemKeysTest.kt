package io.github.kostack.jwt_security.utils

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.EnumSource
import java.security.Key
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.util.Base64
import kotlin.test.assertFailsWith

class PemKeysTest {
  @ParameterizedTest
  @EnumSource(KeyType::class)
  fun `parses RSA keys from Base64 encoded PEM`(type: KeyType) {
    val expected = type.key(rsaKeys)

    val result = type.parse(encode(pem(type.label, Base64.getEncoder().encodeToString(expected.encoded))))

    assertThat(result.algorithm).isEqualTo("RSA")
    assertThat(result.format).isEqualTo(expected.format)
    assertThat(result.encoded).isEqualTo(expected.encoded)
  }

  @ParameterizedTest
  @EnumSource(KeyType::class)
  fun `accepts PEM with wrapped payloads and Windows line endings`(type: KeyType) {
    val expected = type.key(rsaKeys)
    val payload = Base64.getMimeEncoder(64, byteArrayOf(10)).encodeToString(expected.encoded)
    val encodedPem = encode(pem(type.label, payload).replace("\n", "\r\n"))

    assertThat(type.parse(encodedPem).encoded).isEqualTo(expected.encoded)
  }

  @ParameterizedTest
  @EnumSource(KeyType::class)
  fun `rejects valid PEM containing corrupt DER data`(type: KeyType) {
    val corruptPayload = Base64.getEncoder().encodeToString(byteArrayOf(1, 2, 3, 4))

    assertFailsWith<IllegalArgumentException> { type.parse(encode(pem(type.label, corruptPayload))) }
  }

  @ParameterizedTest
  @EnumSource(KeyType::class)
  fun `rejects invalid Base64 inside valid PEM headers`(type: KeyType) {
    assertFailsWith<IllegalArgumentException> { type.parse(encode(pem(type.label, "not-base64!"))) }
  }

  @ParameterizedTest
  @EnumSource(KeyType::class)
  fun `rejects EC keys with otherwise valid encoding and PEM headers`(type: KeyType) {
    val payload = Base64.getEncoder().encodeToString(type.key(ecKeys).encoded)

    assertFailsWith<IllegalArgumentException> { type.parse(encode(pem(type.label, payload))) }
  }

  @ParameterizedTest
  @EnumSource(KeyType::class)
  fun `rejects raw PEM without the outer Base64 encoding`(type: KeyType) {
    val payload = Base64.getEncoder().encodeToString(type.key(rsaKeys).encoded)

    assertFailsWith<IllegalArgumentException> { type.parse(pem(type.label, payload)) }
  }

  @ParameterizedTest
  @EnumSource(KeyType::class)
  fun `rejects Base64 encoded DER without PEM headers`(type: KeyType) {
    val encodedDer = Base64.getEncoder().encodeToString(type.key(rsaKeys).encoded)

    assertFailsWith<IllegalArgumentException> { type.parse(encodedDer) }
  }

  enum class KeyType(
    val label: String
  ) {
    PUBLIC("PUBLIC KEY"),
    PRIVATE("PRIVATE KEY");

    fun key(pair: KeyPair): Key =
      when (this) {
        PUBLIC -> pair.public
        PRIVATE -> pair.private
      }

    fun parse(encodedPem: String): Key =
      when (this) {
        PUBLIC -> PemKeys.publicKey(encodedPem)
        PRIVATE -> PemKeys.privateKey(encodedPem)
      }
  }

  companion object {
    private val rsaKeys by lazy { KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair() }
    private val ecKeys by lazy { KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair() }

    private fun pem(
      label: String,
      payload: String
    ): String = "-----BEGIN $label-----\n$payload\n-----END $label-----\n"

    private fun encode(value: String): String = Base64.getEncoder().encodeToString(value.toByteArray(Charsets.UTF_8))
  }
}
