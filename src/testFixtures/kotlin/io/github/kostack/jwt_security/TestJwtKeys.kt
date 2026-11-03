package io.github.kostack.jwt_security

import java.security.KeyPairGenerator
import java.util.Base64

/** Temporary signing keys shared by the fixture application and its tests for this JVM. */
object TestJwtKeys {
  val properties: Map<String, Any> by lazy {
    val pair = KeyPairGenerator.getInstance("RSA").apply { initialize(4096) }.generateKeyPair()
    mapOf(
      "kostack-security.issuer.private-key" to encodedPem("PRIVATE KEY", pair.private.encoded),
      "kostack-security.public-keys.local" to encodedPem("PUBLIC KEY", pair.public.encoded)
    )
  }

  private fun encodedPem(
    label: String,
    encoded: ByteArray
  ): String {
    val body = Base64.getMimeEncoder(64, byteArrayOf(10)).encodeToString(encoded)
    val pem = "-----BEGIN $label-----\n$body\n-----END $label-----\n"
    return Base64.getEncoder().encodeToString(pem.toByteArray(Charsets.UTF_8))
  }
}
