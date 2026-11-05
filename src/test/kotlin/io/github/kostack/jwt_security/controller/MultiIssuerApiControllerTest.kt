package io.github.kostack.jwt_security.controller

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.sun.net.httpserver.HttpServer
import io.github.kostack.jwt_security.TestApplication
import io.github.kostack.jwt_security.encoder.JwtEncoder
import kotlinx.coroutines.runBlocking
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.web.server.LocalServerPort
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.springframework.test.web.reactive.server.WebTestClient
import java.net.InetSocketAddress
import java.time.Instant
import java.util.Date

@SpringBootTest(
  classes = [TestApplication::class],
  webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
  properties = ["spring.shell.interactive.enabled=false"]
)
class MultiIssuerApiControllerTest {
  @Autowired lateinit var encoder: JwtEncoder

  @LocalServerPort
  private var port: Int = 0

  @ParameterizedTest
  @ValueSource(strings = ["users", "partners"])
  fun `accepts tokens from each configured issuer and loads the user`(name: String) {
    request(token(name))
      .expectStatus()
      .isOk
      .expectBody()
      .jsonPath("$.username")
      .isEqualTo("alice")
  }

  @ParameterizedTest
  @ValueSource(strings = ["users", "partners"])
  fun `direct decoding verifies tokens from each remote issuer`(name: String): Unit =
    runBlocking {
      assertThat(encoder.decode(token(name)).subject).isEqualTo("alice")
    }

  @Test
  fun `accepts query tokens through the issuer resolver`() {
    client()
      .get()
      .uri { it.path("/api").queryParam("token", token("partners")).build() }
      .exchange()
      .expectStatus()
      .isOk
  }

  @Test
  fun `rejects unknown issuers even when signed with a trusted key`() {
    request(token("users", issuer = "https://unknown.example.com")).expectStatus().isUnauthorized
  }

  @Test
  fun `rejects tokens using another issuer's key even with the same kid`() {
    request(token("users", key = partnersKey)).expectStatus().isUnauthorized
  }

  @Test
  fun `rejects algorithms other than the configured algorithm`() {
    request(token("users", algorithm = JWSAlgorithm.RS256)).expectStatus().isUnauthorized
  }

  @Test
  fun `rejects another issuer's audience`() {
    request(token("users", audience = "partners-api")).expectStatus().isUnauthorized
  }

  @Test
  fun `rejects expired tokens`() {
    request(token("users", expiresAt = Instant.now().minusSeconds(120))).expectStatus().isUnauthorized
  }

  @Test
  fun `rejects missing required claims`() {
    request(token("users", roles = null)).expectStatus().isUnauthorized
  }

  @Test
  fun `preserves token authorities for method authorization`() {
    request(token("partners", roles = listOf("ROLE_USER"))).expectStatus().isForbidden
  }

  @Test
  fun `rejects malformed tokens`() {
    request("invalid").expectStatus().isUnauthorized
  }

  private fun client(): WebTestClient = WebTestClient.bindToServer().baseUrl("http://localhost:$port").build()

  private fun request(token: String): WebTestClient.ResponseSpec =
    client()
      .get()
      .uri("/api")
      .header("x-auth", token)
      .exchange()

  private fun token(
    name: String,
    issuer: String = "https://$name.example.com",
    audience: String = "$name-api",
    algorithm: JWSAlgorithm = if (name == "users") JWSAlgorithm.RS512 else JWSAlgorithm.RS256,
    key: RSAKey = if (name == "users") usersKey else partnersKey,
    expiresAt: Instant = Instant.now().plusSeconds(300),
    roles: List<String>? = listOf("ROLE_ADMIN")
  ): String {
    val claims =
      JWTClaimsSet
        .Builder()
        .issuer(issuer)
        .subject("alice")
        .audience(audience)
        .expirationTime(Date.from(expiresAt))
    if (roles != null) claims.claim("roles", roles)
    return SignedJWT(JWSHeader.Builder(algorithm).keyID("shared-kid").build(), claims.build())
      .apply { sign(RSASSASigner(key)) }
      .serialize()
  }

  companion object {
    private val usersKey = RSAKeyGenerator(2048).keyID("shared-kid").keyUse(KeyUse.SIGNATURE).generate()
    private val partnersKey = RSAKeyGenerator(2048).keyID("shared-kid").keyUse(KeyUse.SIGNATURE).generate()
    private val jwksServer =
      HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0).apply {
        mapOf("users" to usersKey, "partners" to partnersKey).forEach { (name, key) ->
          createContext("/$name/jwks") { exchange ->
            val body = JWKSet(key.toPublicJWK()).toString().toByteArray(Charsets.UTF_8)
            exchange.responseHeaders.set("Content-Type", "application/json")
            exchange.sendResponseHeaders(200, body.size.toLong())
            exchange.responseBody.use { it.write(body) }
          }
        }
        start()
      }

    @JvmStatic
    @DynamicPropertySource
    fun issuers(registry: DynamicPropertyRegistry) {
      mapOf("users" to "RS512", "partners" to "RS256").forEach { (name, algorithm) ->
        val prefix = "kostack-security.trusted-issuers.$name"
        registry.add("$prefix.issuer") { "https://$name.example.com" }
        registry.add("$prefix.jwk-set-uri") { "http://127.0.0.1:${jwksServer.address.port}/$name/jwks" }
        registry.add("$prefix.algorithm") { algorithm }
        registry.add("$prefix.audience") { "$name-api" }
      }
    }

    @JvmStatic
    @AfterAll
    fun stopJwksServer() {
      jwksServer.stop(0)
    }
  }
}
