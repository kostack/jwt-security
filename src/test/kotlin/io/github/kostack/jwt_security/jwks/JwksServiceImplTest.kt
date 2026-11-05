package io.github.kostack.jwt_security.jwks

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.github.kostack.jwt_security.TestJwtKeys
import io.github.kostack.jwt_security.autoconfigure.SecurityProperties
import io.github.kostack.jwt_security.service.JwtKeyResolver
import io.github.kostack.jwt_security.utils.PemKeys
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.EnumSource
import org.junit.jupiter.params.provider.ValueSource
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm
import java.util.Base64
import kotlin.test.assertFailsWith

class JwksServiceImplTest {
  private val encodedKey =
    TestJwtKeys.properties.getValue(
      "kostack-security.trusted-issuers.local.public-key"
    ) as String
  private val properties = SecurityProperties()
  private val service = JwksServiceImpl(properties, JwtKeyResolver(properties))

  @Test
  fun `exports inline keys with each issuer's key ID and algorithm without private material`() {
    val secondKey = RSAKeyGenerator(2048).generate().toRSAPublicKey()
    val secondPem =
      "-----BEGIN PUBLIC KEY-----\n" +
        Base64.getEncoder().encodeToString(secondKey.encoded) + "\n-----END PUBLIC KEY-----\n"
    val secondEncodedKey = Base64.getEncoder().encodeToString(secondPem.toByteArray(Charsets.UTF_8))
    properties.trustedIssuers =
      mapOf(
        "first" to SecurityProperties.TrustedIssuer(issuer = "first-issuer", publicKey = encodedKey),
        "second" to
          SecurityProperties.TrustedIssuer(
            issuer = "second-issuer",
            publicKey = secondEncodedKey,
            algorithm = SignatureAlgorithm.RS256
          ),
        "remote" to SecurityProperties.TrustedIssuer(issuer = "remote-issuer", jwkSetUri = "https://remote.test/jwks")
      )

    val result = JWKSet.parse(service.publicKeys())

    assertThat(result.keys.map { it.keyID }).containsExactly("first-issuer", "second-issuer")
    assertThat(result.getKeyByKeyId("first-issuer").algorithm).isEqualTo(JWSAlgorithm.RS512)
    assertThat(result.getKeyByKeyId("second-issuer").algorithm).isEqualTo(JWSAlgorithm.RS256)
    result.keys.forEach { key ->
      assertThat(key.keyUse).isEqualTo(KeyUse.SIGNATURE)
      assertThat(key.isPrivate).isFalse()
      val expectedKey = if (key.keyID == "first-issuer") PemKeys.publicKey(encodedKey) else secondKey
      assertThat(key.toRSAKey().toRSAPublicKey().encoded).isEqualTo(expectedKey.encoded)
    }
  }

  @ParameterizedTest
  @EnumSource(SignatureAlgorithm::class, names = ["RS256", "RS384", "RS512"])
  fun `exported RSA key verifies signatures for the configured algorithm`(algorithm: SignatureAlgorithm) {
    properties.trustedIssuers =
      mapOf(
        "alias" to
          SecurityProperties.TrustedIssuer(
            issuer = "signing-issuer",
            publicKey = encodedKey,
            algorithm = algorithm
          )
      )
    val privateKey =
      PemKeys.privateKey(
        TestJwtKeys.properties.getValue("kostack-security.issuer.private-key") as String
      )
    val token =
      SignedJWT(
        JWSHeader.Builder(JWSAlgorithm.parse(algorithm.name)).keyID("signing-issuer").build(),
        JWTClaimsSet
          .Builder()
          .issuer("signing-issuer")
          .subject("alice")
          .build()
      ).apply { sign(RSASSASigner(privateKey)) }

    val exportedKey = JWKSet.parse(service.publicKeys()).getKeyByKeyId("signing-issuer").toRSAKey()

    assertThat(exportedKey.algorithm.name).isEqualTo(algorithm.name)
    assertThat(token.verify(RSASSAVerifier(exportedKey))).isTrue()
  }

  @ParameterizedTest
  @ValueSource(strings = ["", " ", "\t\n"])
  fun `omits issuers with blank inline keys`(publicKey: String) {
    properties.trustedIssuers =
      mapOf(
        "blank" to SecurityProperties.TrustedIssuer(issuer = "blank", publicKey = publicKey),
        "valid" to SecurityProperties.TrustedIssuer(issuer = "valid", publicKey = encodedKey)
      )
    assertThat(JWKSet.parse(service.publicKeys()).keys.map { it.keyID }).containsExactly("valid")
  }

  @Test
  fun `rejects a private key configured as a public key`() {
    properties.trustedIssuers =
      mapOf(
        "private" to
          SecurityProperties.TrustedIssuer(
            issuer = "private",
            publicKey = TestJwtKeys.properties.getValue("kostack-security.issuer.private-key") as String
          )
      )
    assertFailsWith<IllegalArgumentException> { service.publicKeys() }
  }

  @Test
  fun `returns an empty key set when no inline keys are configured`() {
    assertThat(JWKSet.parse(service.publicKeys()).keys).isEmpty()
    properties.trustedIssuers =
      mapOf(
        "remote" to SecurityProperties.TrustedIssuer(issuer = "remote", jwkSetUri = "https://remote.test/jwks")
      )
    assertThat(JWKSet.parse(service.publicKeys()).keys).isEmpty()
  }

  @Test
  fun `rejects malformed inline public keys`() {
    properties.trustedIssuers =
      mapOf(
        "broken" to SecurityProperties.TrustedIssuer(issuer = "broken", publicKey = "invalid")
      )
    assertFailsWith<IllegalArgumentException> { service.publicKeys() }
  }
}
