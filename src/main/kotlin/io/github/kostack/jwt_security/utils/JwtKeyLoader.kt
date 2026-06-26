package io.github.kostack.jwt_security.utils

import java.nio.file.Files
import java.nio.file.Paths
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

object JwtKeyLoader {
  fun getPrivateKey(privateKeyPath: String): PrivateKey {
    val privateKeyContent =
      Files
        .readString(Paths.get(privateKeyPath))
        .replace("-----BEGIN PRIVATE KEY-----", "")
        .replace("-----END PRIVATE KEY-----", "")
        .replace(Regex("\\s"), "") // removes all whitespace, not just line breaks

    val encoded = Base64.getDecoder().decode(privateKeyContent)

    val keyFactory = KeyFactory.getInstance("RSA")
    val keySpec = PKCS8EncodedKeySpec(encoded)
    return keyFactory.generatePrivate(keySpec)
  }

  fun getPublicKey(publicKeyPath: String): PublicKey {
    val publicKeyContent =
      Files
        .readString(Paths.get(publicKeyPath))
        .replace("-----BEGIN PUBLIC KEY-----", "")
        .replace("-----END PUBLIC KEY-----", "")
        .replace(Regex("\\s"), "")

    val keyBytes = Base64.getDecoder().decode(publicKeyContent)

    val keyFactory = KeyFactory.getInstance("RSA")
    val keySpec = X509EncodedKeySpec(keyBytes)
    return keyFactory.generatePublic(keySpec)
  }
}
