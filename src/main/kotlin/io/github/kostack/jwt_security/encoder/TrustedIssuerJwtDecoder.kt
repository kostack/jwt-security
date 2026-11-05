package io.github.kostack.jwt_security.encoder

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.JWKSecurityContextJWKSet
import com.nimbusds.jose.proc.JWSVerificationKeySelector
import com.nimbusds.jwt.SignedJWT
import io.github.kostack.jwt_security.autoconfigure.SecurityProperties
import io.github.kostack.jwt_security.service.JwtKeyResolver
import org.springframework.security.oauth2.jwt.BadJwtException
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtIssuerValidator
import org.springframework.security.oauth2.jwt.JwtTimestampValidator
import org.springframework.security.oauth2.jwt.JwtValidators
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder
import reactor.core.publisher.Flux
import reactor.core.publisher.Mono
import java.net.URI
import java.time.Clock
import java.time.Duration

class TrustedIssuerJwtDecoder(
  properties: SecurityProperties,
  keyResolver: JwtKeyResolver,
  clock: Clock,
  claimsValidator: JwtClaimsValidator
) : ReactiveJwtDecoder {
  private val decoders: Map<String, ReactiveJwtDecoder>

  init {
    val configured = mutableMapOf<String, ReactiveJwtDecoder>()
    properties.trustedIssuers.forEach { (name, issuer) ->
      require(issuer.issuer.isNotBlank()) { "Trusted issuer '$name' must define issuer" }
      require(issuer.audience.isNotBlank()) { "Trusted issuer '$name' must define audience" }
      require(!configured.containsKey(issuer.issuer)) { "Duplicate trusted issuer: ${issuer.issuer}" }
      require(issuer.jwkSetUri.isNotBlank() != issuer.publicKey.isNotBlank()) {
        "Trusted issuer '$name' must define exactly one of jwk-set-uri or public-key"
      }
      val decoder =
        if (issuer.jwkSetUri.isNotBlank()) {
          val uri = URI(issuer.jwkSetUri)
          require(uri.scheme in setOf("https", "http") && !uri.host.isNullOrBlank()) {
            "Trusted issuer '$name' must define an absolute HTTP(S) jwk-set-uri"
          }
          NimbusReactiveJwtDecoder.withJwkSetUri(issuer.jwkSetUri).jwsAlgorithm(issuer.algorithm).build()
        } else {
          require(issuer.algorithm.name in setOf("RS256", "RS384", "RS512")) {
            "Trusted issuer '$name' with an inline public key must use RS256, RS384, or RS512"
          }
          NimbusReactiveJwtDecoder
            .withJwkSource { jwt ->
              Flux
                .defer<JWK> {
                  val kid = jwt.header.keyID ?: return@defer Flux.empty()
                  Flux.just(
                    RSAKey
                      .Builder(keyResolver.publicKey(kid, issuer.issuer))
                      .keyID(kid)
                      .algorithm(JWSAlgorithm.parse(issuer.algorithm.name))
                      .build()
                  )
                }.onErrorResume(IllegalArgumentException::class.java) { Flux.empty() }
            }.jwtProcessorCustomizer { processor ->
              processor.jwsKeySelector =
                JWSVerificationKeySelector(
                  JWSAlgorithm.parse(issuer.algorithm.name),
                  JWKSecurityContextJWKSet()
                )
            }.build()
        }
      decoder.setJwtValidator(
        JwtValidators.createDefaultWithValidators(
          JwtIssuerValidator(issuer.issuer),
          JwtTimestampValidator(Duration.ZERO).apply { setClock(clock) },
          claimsValidator
        )
      )
      configured[issuer.issuer] = decoder
    }
    decoders = configured
  }

  override fun decode(token: String): Mono<Jwt> =
    Mono.defer {
      val issuer =
        try {
          SignedJWT.parse(token).jwtClaimsSet.issuer
        } catch (ex: Exception) {
          return@defer Mono.error(BadJwtException("Invalid JWT", ex))
        }
      val decoder = decoders[issuer] ?: return@defer Mono.error(BadJwtException("Untrusted JWT issuer"))
      decoder.decode(token)
    }
}
