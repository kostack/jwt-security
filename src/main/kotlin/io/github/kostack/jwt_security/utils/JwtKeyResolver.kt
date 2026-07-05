package io.github.kostack.jwt_security.utils

import io.github.kostack.jwt_security.autoconfigure.JwtProperties
import jakarta.annotation.PostConstruct
import org.slf4j.LoggerFactory
import java.nio.file.Path
import java.security.PrivateKey
import java.security.PublicKey

class JwtKeyResolver(
  private val jwtProperties: JwtProperties
) {
  var privateKey: PrivateKey? = null

  private val publicKeyResolverMap: MutableMap<String, PublicKey> = mutableMapOf()

  @PostConstruct
  fun init() {
    runCatching {
      privateKey =
        JwtKeyLoader.getPrivateKey(
          Path.of(jwtProperties.privateKey).toString()
        )
    }.onFailure {
      log.warn("Failed to initialize private JWT key: ${it.stackTraceToString()}")
    }

    runCatching {
      jwtProperties.publicKeys.forEach { (issuer, path) ->
        publicKeyResolverMap[issuer] = JwtKeyLoader.getPublicKey(path)
      }
    }.onFailure {
      log.error("Failed to initialize public JWT key: ${it.stackTraceToString()}")
    }
  }

  fun getPublicKeyBasedOnIssuer(issuer: String): PublicKey =
    publicKeyResolverMap[issuer]
      ?: throw RuntimeException("No public key found for issuer: $issuer")

  companion object {
    private val log = LoggerFactory.getLogger(JwtKeyResolver::class.java)
  }
}
