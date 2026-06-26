package io.github.kostack.jwt_security.service

import io.github.kostack.jwt_security.configuration.JwtProperties
import io.github.kostack.jwt_security.utils.IssuerKeyLocator
import io.github.kostack.jwt_security.utils.JwtKeyResolver
import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jws
import io.jsonwebtoken.Jwts
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import java.time.Instant
import java.util.Date

@Service
class JwtManager(
  private val jwtProperties: JwtProperties,
  private val jwtKeyResolver: JwtKeyResolver,
  private val issuerKeyLocator: IssuerKeyLocator
) {
  fun generateToken(user: JwtUser): String {
    val now = Instant.now()
    val exp = now.plusSeconds(jwtProperties.expiration.toLong())

    return Jwts
      .builder()
      .header()
      .keyId(jwtProperties.issuer)
      .and()
      .subject(user.identity)
      .claims(user.toMap())
      .issuer(jwtProperties.issuer)
      .issuedAt(Date.from(now))
      .expiration(Date.from(exp))
      .signWith(jwtKeyResolver.privateKey, jwtProperties.getSignatureAlgorithm())
      .compact()
  }

  fun validateJwtToken(token: String): Boolean =
    try {
      getClaims(token)
      true
    } catch (e: Exception) {
      log.info("Invalid JWT token: {}", e.message)
      false
    }

  fun getClaims(token: String): Jws<Claims> =
    Jwts
      .parser()
      .keyLocator(issuerKeyLocator)
      .build()
      .parseSignedClaims(token)

  companion object {
    private val log = LoggerFactory.getLogger(JwtManager::class.java)
  }
}
