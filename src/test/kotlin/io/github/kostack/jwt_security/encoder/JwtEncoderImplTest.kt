package io.github.kostack.jwt_security.encoder

import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jwt.SignedJWT
import io.github.kostack.jwt_security.TestJwtKeys
import io.github.kostack.jwt_security.autoconfigure.SecurityProperties
import io.github.kostack.jwt_security.dto.JwtUser
import io.github.kostack.jwt_security.service.JwtKeyResolver
import io.jsonwebtoken.Jwts
import kotlinx.coroutines.runBlocking
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.EnumSource
import org.junit.jupiter.params.provider.ValueSource
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm
import org.springframework.security.oauth2.jwt.JwtException
import org.springframework.security.oauth2.jwt.JwtValidationException
import java.security.KeyPairGenerator
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.Date
import kotlin.test.assertFailsWith

class JwtEncoderImplTest {
  private val now = Instant.parse("2020-01-01T00:00:00Z")
  private val clock = Clock.fixed(now, ZoneOffset.UTC)
  private val properties =
    SecurityProperties(
      issuer =
        SecurityProperties.Issuer(
          kid = "test-key",
          name = "https://issuer.test",
          audience = "test-api",
          privateKey = TestJwtKeys.properties.getValue("kostack-security.issuer.private-key") as String,
          expirationTime = 300
        ),
      publicKeys =
        mapOf("test-key" to TestJwtKeys.properties.getValue("kostack-security.public-keys.local") as String)
    )
  private val resolver = JwtKeyResolver(properties)
  private val encoder = JwtEncoderImpl(resolver, properties, clock, RequiredJwtClaimsValidator(properties))
  private val user =
    object : JwtUser {
      override val identity = "user-123"

      override fun claims(): Map<String, Any> = mapOf("roles" to listOf("ROLE_USER"), "name" to "Alice")
    }

  @ParameterizedTest
  @EnumSource(SignatureAlgorithm::class, names = ["RS256", "RS384", "RS512"])
  fun `encodes with the configured algorithm and key ID`(algorithm: SignatureAlgorithm): Unit =
    runBlocking {
      properties.issuer.algorithmSignature = algorithm

      val signed = SignedJWT.parse(encoder.encode(user))

      assertThat(signed.header.algorithm.name).isEqualTo(algorithm.name)
      assertThat(signed.header.keyID).isEqualTo("test-key")
      assertThat(signed.verify(RSASSAVerifier(resolver.publicKey("test-key")))).isTrue()
    }

  @Test
  fun `encodes user claims and configured registered claims using the injected clock`(): Unit =
    runBlocking {
      val claims = SignedJWT.parse(encoder.encode(user, mapOf("tenant" to "acme"))).jwtClaimsSet

      assertThat(claims.subject).isEqualTo(user.identity)
      assertThat(claims.issuer).isEqualTo(properties.issuer.name)
      assertThat(claims.audience).containsExactly(properties.issuer.audience)
      assertThat(claims.issueTime.toInstant()).isEqualTo(now)
      assertThat(claims.notBeforeTime.toInstant()).isEqualTo(now.minusSeconds(1))
      assertThat(claims.expirationTime.toInstant()).isEqualTo(now.plusSeconds(300))
      assertThat(claims.getStringListClaim("roles")).containsExactly("ROLE_USER")
      assertThat(claims.getStringClaim("name")).isEqualTo("Alice")
      assertThat(claims.getStringClaim("tenant")).isEqualTo("acme")
    }

  @Test
  fun `null expiration uses the configured lifetime`(): Unit =
    runBlocking {
      properties.issuer.expirationTime = 900

      val claims = SignedJWT.parse(encoder.encode(user, expiration = null)).jwtClaimsSet

      assertThat(claims.expirationTime.toInstant()).isEqualTo(now.plusSeconds(900))
    }

  @ParameterizedTest
  @ValueSource(longs = [60, 600])
  fun `custom expiration overrides configured lifetime and additional exp claim for one token`(expiration: Long): Unit =
    runBlocking {
      val token = encoder.encode(user, mapOf("exp" to 1L, "tenant" to "acme"), expiration = expiration)
      val jwt = encoder.decode(token)

      assertThat(jwt.issuedAt).isEqualTo(now)
      assertThat(jwt.expiresAt).isEqualTo(now.plusSeconds(expiration))
      assertThat(jwt.getClaimAsString("tenant")).isEqualTo("acme")
      assertThat(properties.issuer.expirationTime).isEqualTo(300)
      assertThat(encoder.decode(encoder.encode(user)).expiresAt).isEqualTo(now.plusSeconds(300))
    }

  @Test
  fun `rejects an encoded token after its custom lifetime expires`(): Unit =
    runBlocking {
      val token = encoder.encode(user, expiration = 60L)
      val laterEncoder =
        JwtEncoderImpl(
          resolver,
          properties,
          Clock.fixed(now.plusSeconds(61), ZoneOffset.UTC),
          RequiredJwtClaimsValidator(properties)
        )

      assertFailsWith<JwtValidationException> { laterEncoder.decode(token) }
    }

  @Test
  fun `additional claims override user claims`(): Unit =
    runBlocking {
      val jwt = encoder.decode(encoder.encode(user, mapOf("roles" to listOf("ROLE_ADMIN"), "name" to "Bob")))

      assertThat(jwt.getClaimAsStringList("roles")).containsExactly("ROLE_ADMIN")
      assertThat(jwt.getClaimAsString("name")).isEqualTo("Bob")
    }

  @Test
  fun `identity issuer and timestamps override additional claims`(): Unit =
    runBlocking {
      val claims =
        SignedJWT
          .parse(
            encoder.encode(
              user,
              mapOf("sub" to "attacker", "iss" to "other", "iat" to 1L, "nbf" to 1L, "exp" to 2L)
            )
          ).jwtClaimsSet

      assertThat(claims.subject).isEqualTo(user.identity)
      assertThat(claims.issuer).isEqualTo(properties.issuer.name)
      assertThat(claims.issueTime.toInstant()).isEqualTo(now)
      assertThat(claims.notBeforeTime.toInstant()).isEqualTo(now.minusSeconds(1))
      assertThat(claims.expirationTime.toInstant()).isEqualTo(now.plusSeconds(300))
    }

  @ParameterizedTest
  @EnumSource(SignatureAlgorithm::class, names = ["RS256", "RS384", "RS512"])
  fun `decodes tokens signed with supported RSA algorithms`(algorithm: SignatureAlgorithm): Unit =
    runBlocking {
      properties.issuer.algorithmSignature = algorithm
      val token = encoder.encode(user)

      val jwt = encoder.decode(token)

      assertThat(jwt.tokenValue).isEqualTo(token)
      assertThat(jwt.subject).isEqualTo(user.identity)
      assertThat(jwt.headers["kid"]).isEqualTo("test-key")
    }

  @Test
  fun `exposes a reactive decoder with the same validation`(): Unit =
    runBlocking {
      val token = encoder.encode(user)

      assertThat(
        encoder
          .decoder()
          .decode(token)
          .block()!!
          .subject
      ).isEqualTo(user.identity)
      assertFailsWith<JwtException> { encoder.decoder().decode("invalid").block() }
    }

  @Test
  fun `resolves the verification key using the token key ID`(): Unit =
    runBlocking {
      properties.publicKeys = properties.publicKeys + ("rotated-key" to properties.publicKeys.getValue("test-key"))

      assertThat(encoder.decode(token(kid = "rotated-key")).subject).isEqualTo(user.identity)
    }

  @Test
  fun `rejects a token without a key ID`(): Unit =
    runBlocking {
      assertFailsWith<JwtException> { encoder.decode(token(kid = null)) }
    }

  @Test
  fun `rejects a token with an unknown key ID`(): Unit =
    runBlocking {
      assertFailsWith<JwtException> { encoder.decode(token(kid = "unknown")) }
    }

  @Test
  fun `rejects a signature from another RSA key`(): Unit =
    runBlocking {
      val otherKey =
        KeyPairGenerator
          .getInstance("RSA")
          .apply { initialize(2048) }
          .generateKeyPair()
          .private
      val token =
        Jwts
          .builder()
          .header()
          .keyId("test-key")
          .and()
          .claims(validClaims())
          .signWith(otherKey, Jwts.SIG.RS256)
          .compact()

      assertFailsWith<JwtException> { encoder.decode(token) }
    }

  @Test
  fun `rejects HMAC tokens even with a known key ID`(): Unit =
    runBlocking {
      val token =
        Jwts
          .builder()
          .header()
          .keyId("test-key")
          .and()
          .claims(validClaims())
          .signWith(
            Jwts.SIG.HS256
              .key()
              .build()
          ).compact()

      assertFailsWith<JwtException> { encoder.decode(token) }
    }

  @Test
  fun `rejects unsigned tokens`(): Unit =
    runBlocking {
      val token = Jwts.builder().claims(validClaims()).compact()

      assertFailsWith<JwtException> { encoder.decode(token) }
    }

  @ParameterizedTest
  @ValueSource(strings = ["", "invalid", "a.b.c"])
  fun `rejects malformed tokens`(token: String): Unit =
    runBlocking {
      assertFailsWith<JwtException> { encoder.decode(token) }
    }

  @Test
  fun `rejects an incorrect issuer`(): Unit =
    runBlocking {
      assertFailsWith<JwtValidationException> { encoder.decode(token(mapOf("iss" to "https://other.test"))) }
    }

  @Test
  fun `rejects tokens expired by one second without clock skew`(): Unit =
    runBlocking {
      assertFailsWith<JwtValidationException> {
        encoder.decode(token(mapOf("iat" to Date.from(now.minusSeconds(60)), "exp" to Date.from(now.minusSeconds(1)))))
      }
    }

  @Test
  fun `rejects tokens that become valid one second in the future without clock skew`(): Unit =
    runBlocking {
      assertFailsWith<JwtValidationException> { encoder.decode(token(mapOf("nbf" to Date.from(now.plusSeconds(1))))) }
    }

  @ParameterizedTest
  @ValueSource(strings = ["roles", "exp", "sub", "aud"])
  fun `rejects tokens missing required claims`(claim: String): Unit =
    runBlocking {
      assertFailsWith<JwtValidationException> { encoder.decode(token(omittedClaim = claim)) }
    }

  @Test
  fun `rejects an incorrect audience`(): Unit =
    runBlocking {
      assertFailsWith<JwtValidationException> { encoder.decode(token(mapOf("aud" to listOf("other-api")))) }
    }

  @Test
  fun `applies the supplied claims validator and preserves its error`(): Unit =
    runBlocking {
      val error = OAuth2Error("invalid_token", "Tenant is disabled", null)
      val validator = JwtClaimsValidator { OAuth2TokenValidatorResult.failure(error) }
      val customEncoder = JwtEncoderImpl(resolver, properties, clock, validator)

      val failure = assertFailsWith<JwtValidationException> { customEncoder.decode(token()) }

      assertThat(failure.errors).contains(error)
    }

  @Test
  fun `propagates an invalid signing key failure`(): Unit =
    runBlocking {
      properties.issuer.privateKey = "invalid"

      assertFailsWith<IllegalStateException> { encoder.encode(user) }
    }

  @ParameterizedTest
  @ValueSource(strings = ["2000-01-01T00:00:00Z", "2100-01-01T00:00:00Z"])
  fun `decodes valid tokens using the injected clock independently of the system clock`(instant: String): Unit =
    runBlocking {
      val fixedClock = Clock.fixed(Instant.parse(instant), ZoneOffset.UTC)
      val fixedClockEncoder =
        JwtEncoderImpl(resolver, properties, fixedClock, RequiredJwtClaimsValidator(properties))
      assertThat(fixedClockEncoder.decode(fixedClockEncoder.encode(user)).subject).isEqualTo(user.identity)
    }

  private fun validClaims(): Map<String, Any> =
    mapOf(
      "sub" to user.identity,
      "iss" to properties.issuer.name,
      "aud" to listOf(properties.issuer.audience),
      "iat" to Date.from(now.minusSeconds(10)),
      "nbf" to Date.from(now.minusSeconds(1)),
      "exp" to Date.from(now.plusSeconds(300)),
      "roles" to listOf("ROLE_USER")
    )

  private fun token(
    overrides: Map<String, Any> = emptyMap(),
    kid: String? = "test-key",
    omittedClaim: String? = null
  ): String =
    Jwts
      .builder()
      .header()
      .keyId(kid)
      .and()
      .claims((validClaims() + overrides).filterKeys { it != omittedClaim })
      .signWith(resolver.privateKey(), Jwts.SIG.RS512)
      .compact()
}
