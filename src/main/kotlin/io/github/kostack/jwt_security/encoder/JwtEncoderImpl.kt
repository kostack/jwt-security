package io.github.kostack.jwt_security.encoder

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.github.kostack.jwt_security.autoconfigure.SecurityProperties
import io.github.kostack.jwt_security.dto.JwtUser
import io.github.kostack.jwt_security.service.JwtKeyResolver
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.reactor.awaitSingle
import kotlinx.coroutines.withContext
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder
import java.time.Clock
import java.time.Instant
import java.util.Date

class JwtEncoderImpl(
  private val keyResolver: JwtKeyResolver,
  private val properties: SecurityProperties,
  private val clock: Clock,
  private val claimsValidator: JwtClaimsValidator
) : JwtEncoder {
  init {
    signingAlgorithm()
  }

  private fun signingAlgorithm(): JWSAlgorithm {
    val name = properties.issuer.algorithmSignature.name
    check(name in RSA_ALGORITHMS) {
      "Issuer algorithm-signature must be one of $RSA_ALGORITHMS for an RSA private key, but was $name"
    }
    return JWSAlgorithm.parse(name)
  }

  override suspend fun encode(
    user: JwtUser,
    additionalClaims: Map<String, Any>,
    expiresAt: Instant?
  ): String =
    withContext(Dispatchers.IO) {
      val now = clock.instant()
      val supplied = user.claims() + additionalClaims
      val header =
        JWSHeader
          .Builder(signingAlgorithm())
          .keyID(properties.issuer.kid)
          .type(JOSEObjectType.JWT)
          .build()
      val claims =
        JWTClaimsSet
          .Builder()
          .apply { supplied.forEach { (name, value) -> claim(name, value) } }
          .subject(user.identity)
          .issuer(properties.issuer.kid)
          .audience(audience(supplied[AUDIENCE]))
          .issueTime(Date.from(now))
          .notBeforeTime(Date.from(now.minusSeconds(1)))
          .expirationTime(Date.from(expiresAt ?: now.plusSeconds(properties.issuer.expirationTime)))
          .build()
      SignedJWT(header, claims)
        .apply { sign(RSASSASigner(keyResolver.privateKey())) }
        .serialize()
    }

  private fun audience(supplied: Any?): List<String> =
    when (supplied) {
      is String -> listOf(supplied)
      is Collection<*> -> supplied.filterNotNull().map { it.toString() }
      else -> emptyList()
    }.plus(properties.issuer.audience)
      .filter { it.isNotBlank() }
      .distinct()

  override suspend fun decode(token: String): Jwt = decoder().decode(token).awaitSingle()

  override fun decoder(): ReactiveJwtDecoder = jwtDecoder

  private val jwtDecoder: ReactiveJwtDecoder by lazy {
    TrustedIssuerJwtDecoder(properties, keyResolver, clock, claimsValidator)
  }

  private companion object {
    const val AUDIENCE = "aud"
    val RSA_ALGORITHMS = setOf("RS256", "RS384", "RS512")
  }
}
