package io.github.kostack.jwt_security.service

import io.github.kostack.jwt_security.autoconfigure.SecurityProperties
import io.github.kostack.jwt_security.utils.PemKeys
import org.slf4j.LoggerFactory
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

class JwtKeyResolver(
  private val properties: SecurityProperties
) {
  fun privateKey(): RSAPrivateKey {
    try {
      return PemKeys.privateKey(properties.issuer.privateKey)
    } catch (e: Exception) {
      log.error("Failed to initialize private JWT key: ${e.stackTraceToString()}")
      throw IllegalStateException("Invalid private key", e)
    }
  }

  fun publicKey(kid: String): RSAPublicKey {
    val configuredKey =
      properties.publicKeys[kid]
        ?: throw IllegalArgumentException("No public key found: $kid")
    return PemKeys.publicKey(configuredKey)
  }

  companion object {
    private val log = LoggerFactory.getLogger(JwtKeyResolver::class.java)
  }
}
