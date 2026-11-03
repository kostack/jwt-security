package io.github.kostack.jwt_security.utils

import org.springframework.security.converter.RsaKeyConverters
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.Base64

object PemKeys {
  fun publicKey(encodedPem: String): RSAPublicKey =
    Base64
      .getDecoder()
      .decode(encodedPem.trim())
      .inputStream()
      .use { RsaKeyConverters.x509().convert(it) }

  fun privateKey(encodedPem: String): RSAPrivateKey =
    Base64
      .getDecoder()
      .decode(encodedPem.trim())
      .inputStream()
      .use { RsaKeyConverters.pkcs8().convert(it) }
}
