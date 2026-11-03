package io.github.kostack.jwt_security.controller

import io.github.kostack.jwt_security.TestApplication
import io.github.kostack.jwt_security.TestJwtKeys
import io.github.kostack.jwt_security.encoder.JwtEncoder
import io.github.kostack.jwt_security.model.User
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.web.server.LocalServerPort
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.springframework.test.web.reactive.server.WebTestClient

@SpringBootTest(
  classes = [TestApplication::class],
  webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
  properties = [
    "spring.shell.interactive.enabled=false",
    "spring.shell.noninteractive.enabled=false",
    "spring.shell.script.enabled=false"
  ]
)
class ApiControllerTest {
  @Autowired lateinit var jwtEncoder: JwtEncoder

  @LocalServerPort
  private var port: Int = 0

  private fun client(): WebTestClient = WebTestClient.bindToServer().baseUrl("http://localhost:$port").build()

  private fun token(): String =
    runBlocking {
      jwtEncoder.encode(User("admin", listOf("ROLE_ADMIN")))
    }

  @Test
  fun `generated keys sign and verify query tokens`() {
    client()
      .get()
      .uri { it.path("/api").queryParam("token", token()).build() }
      .exchange()
      .expectStatus()
      .isOk
      .expectBody()
      .jsonPath("$.username")
      .isEqualTo("admin")
  }

  @Test
  fun `generated keys sign and verify header tokens`() {
    client()
      .get()
      .uri("/api")
      .header("x-auth", token())
      .exchange()
      .expectStatus()
      .isOk
      .expectBody()
      .jsonPath("$.username")
      .isEqualTo("admin")
  }

  @Test
  fun `invalid token is unauthorized`() {
    client()
      .get()
      .uri("/api?token=invalid")
      .exchange()
      .expectStatus()
      .isUnauthorized
  }

  companion object {
    @JvmStatic
    @DynamicPropertySource
    fun jwtKeys(registry: DynamicPropertyRegistry) {
      TestJwtKeys.properties.forEach { (name, value) -> registry.add(name) { value } }
    }
  }
}
