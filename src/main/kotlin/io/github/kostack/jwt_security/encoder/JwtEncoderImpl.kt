package io.github.kostack.jwt_security.encoder

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.JWKSecurityContextJWKSet
import com.nimbusds.jose.proc.JWSVerificationKeySelector
import io.github.kostack.jwt_security.autoconfigure.SecurityProperties
import io.github.kostack.jwt_security.dto.JwtUser
import io.github.kostack.jwt_security.service.JwtKeyResolver
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.SignatureAlgorithm
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.reactor.awaitSingle
import kotlinx.coroutines.withContext
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtIssuerValidator
import org.springframework.security.oauth2.jwt.JwtTimestampValidator
import org.springframework.security.oauth2.jwt.JwtValidators
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder
import reactor.core.publisher.Flux
import java.time.Clock
import java.time.Duration
import java.util.Date

class JwtEncoderImpl(
  private val keyResolver: JwtKeyResolver,
  private val properties: SecurityProperties,
  private val clock: Clock,
  private val claimsValidator: JwtClaimsValidator
) : JwtEncoder {
  override suspend fun encode(
    user: JwtUser,
    additionalClaims: Map<String, Any>,
    expiration: Long?
  ): String =
    withContext(Dispatchers.IO) {
      val privateKey = keyResolver.privateKey()
      val algorithm = Jwts.SIG.get().forKey(properties.issuer.algorithmSignature.name) as SignatureAlgorithm
      val now = clock.instant()
      val exp = expiration ?: properties.issuer.expirationTime
      return@withContext Jwts
        .builder()
        .header()
        .keyId(properties.issuer.kid)
        .and()
        .claims(user.claims() + additionalClaims)
        .subject(user.identity)
        .issuer(properties.issuer.name)
        .audience()
        .add(properties.issuer.audience)
        .and()
        .issuedAt(Date.from(now))
        .notBefore(Date.from(now.minusSeconds(1)))
        .expiration(
          Date.from(now.plusSeconds(exp))
        ).signWith(privateKey, algorithm)
        .compact()
    }

  override suspend fun decode(token: String): Jwt = decoder().decode(token).awaitSingle()

  override fun decoder(): ReactiveJwtDecoder =
    NimbusReactiveJwtDecoder
      .withJwkSource { jwt ->
        Flux
          .defer<JWK> {
            val kid = jwt.header.keyID ?: return@defer Flux.empty()
            val algorithm = jwt.header.algorithm
            Flux.just(
              RSAKey
                .Builder(keyResolver.publicKey(kid))
                .keyID(kid)
                .algorithm(algorithm)
                .build()
            )
          }.onErrorResume(IllegalArgumentException::class.java) { Flux.empty() }
      }.jwtProcessorCustomizer { processor ->
        processor.jwsKeySelector =
          JWSVerificationKeySelector(
            JWSAlgorithm.Family.RSA,
            JWKSecurityContextJWKSet()
          )
      }.build()
      .apply {
        setJwtValidator(
          JwtValidators.createDefaultWithValidators(
            JwtIssuerValidator(properties.issuer.name),
            JwtTimestampValidator(Duration.ZERO).apply { setClock(clock) },
            claimsValidator
          )
        )
      }
}
