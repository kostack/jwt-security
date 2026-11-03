package io.github.kostack.jwt_security.controller

import io.github.kostack.jwt_security.TestApplication
import io.github.kostack.jwt_security.service.JwtManager
import io.github.kostack.jwt_security.service.UserProviderImpl
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.MethodOrderer
import org.junit.jupiter.api.Order
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.junit.jupiter.api.TestMethodOrder
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.web.server.LocalServerPort
import org.springframework.http.MediaType
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.test.web.reactive.server.expectBody

@SpringBootTest(
  classes = [TestApplication::class],
  webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT
)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation::class)
class ApiControllerTest {
  @Autowired lateinit var jwtProperties: JwtProperties

  @Autowired lateinit var jwtManager: JwtManager

  @Autowired lateinit var userService: UserProviderImpl

  @LocalServerPort
  protected var port: Int = 0

  fun webTestClient(): WebTestClient = WebTestClient.bindToServer().baseUrl("http://localhost:$port").build()

  @Test
  @Order(1)
  fun `should return default message`() =
    runTest {
      val token = jwtManager.generateToken(userService.findByIdentity("admin-1"))

      webTestClient()
        .get()
        .uri { uriBuilder ->
          uriBuilder
            .path("/api")
            .queryParam("testId", "ok")
            .build()
        }.header("Authorization", "Bearer $token")
        .accept(MediaType.APPLICATION_JSON)
        .exchange()
        .expectStatus()
        .isOk
        .expectBody<String>()
        .value { response ->
          assertEquals(
            "security",
            response
          )
        }
    }

  @Test
  @Order(2)
  fun `should return 401`() =
    runTest {
      val token = "invalid token"

      webTestClient()
        .get()
        .uri { uriBuilder ->
          uriBuilder
            .path("/api")
            .queryParam("testId", "ok")
            .build()
        }.header("Authorization", "Bearer $token")
        .accept(MediaType.APPLICATION_JSON)
        .exchange()
        .expectStatus()
        .isUnauthorized
        .expectBody()
    }
}
