package io.github.kostack.jwt_security.service

import io.github.kostack.jwt_security.autoconfigure.SecurityProperties
import io.github.kostack.jwt_security.utils.PemKeys
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.concurrent.ConcurrentHashMap

class JwtKeyResolver(
  private val properties: SecurityProperties
) {
  private val privateKeys = ConcurrentHashMap<String, RSAPrivateKey>()
  private val publicKeys = ConcurrentHashMap<String, RSAPublicKey>()

  fun privateKey(): RSAPrivateKey {
    val encoded = properties.issuer.privateKey
    return try {
      privateKeys.computeIfAbsent(encoded) { PemKeys.privateKey(it) }
    } catch (e: Exception) {
      throw IllegalStateException("Invalid private key", e)
    }
  }

  fun publicKey(issuer: String = properties.issuer.kid): RSAPublicKey {
    val configuredKey =
      properties.trustedIssuers.values
        .firstOrNull { it.issuer == issuer }
        ?.publicKey
        ?.takeIf { it.isNotBlank() }
        ?: throw IllegalArgumentException("No public key found: $issuer")
    return publicKeys.computeIfAbsent(configuredKey) { PemKeys.publicKey(it) }
  }
}
