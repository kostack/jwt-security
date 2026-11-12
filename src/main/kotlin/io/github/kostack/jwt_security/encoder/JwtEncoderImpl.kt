package io.github.kostack.jwt_security.encoder

import io.github.kostack.jwt_security.autoconfigure.SecurityProperties
import io.github.kostack.jwt_security.dto.JwtUser
import io.github.kostack.jwt_security.service.JwtKeyResolver
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.SignatureAlgorithm
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

  private fun signingAlgorithm(): SignatureAlgorithm {
    val name = properties.issuer.algorithmSignature.name
    check(name in RSA_ALGORITHMS) {
      "Issuer algorithm-signature must be one of $RSA_ALGORITHMS for an RSA private key, but was $name"
    }
    return Jwts.SIG.get().forKey(name) as SignatureAlgorithm
  }

  override suspend fun encode(
    user: JwtUser,
    additionalClaims: Map<String, Any>,
    expiresAt: Instant?
  ): String =
    withContext(Dispatchers.IO) {
      val now = clock.instant()
      val privateKey = keyResolver.privateKey()
      val algorithm = signingAlgorithm()
      return@withContext Jwts
        .builder()
        .header()
        .keyId(properties.issuer.kid)
        .and()
        .claims(user.claims() + additionalClaims)
        .subject(user.identity)
        .issuer(properties.issuer.kid)
        .audience()
        .add(properties.issuer.audience)
        .and()
        .issuedAt(Date.from(now))
        .notBefore(Date.from(now.minusSeconds(1)))
        .expiration(Date.from(expiresAt ?: now.plusSeconds(properties.issuer.expirationTime)))
        .signWith(privateKey, algorithm)
        .compact()
    }

  override suspend fun decode(token: String): Jwt = decoder().decode(token).awaitSingle()

  private val jwtDecoder: ReactiveJwtDecoder by lazy {
    TrustedIssuerJwtDecoder(properties, keyResolver, clock, claimsValidator)
  }

  override fun decoder(): ReactiveJwtDecoder = jwtDecoder

  private companion object {
    val RSA_ALGORITHMS = setOf("RS256", "RS384", "RS512")
  }
}
