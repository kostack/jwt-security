package io.github.kostack.jwt_security.controller

import io.github.kostack.jwt_security.autoconfigure.SecurityProperties
import io.github.kostack.jwt_security.autoconfigure.WebSecurityConfiguration
import io.github.kostack.jwt_security.converter.HeaderOrQueryTokenAuthenticationConverter
import io.github.kostack.jwt_security.service.UserProviderImpl
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test
import org.springframework.context.annotation.AnnotationConfigApplicationContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Import
import org.springframework.security.oauth2.jwt.BadJwtException
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.web.reactive.config.EnableWebFlux
import reactor.core.publisher.Mono

class SuspendControllerSecurityTest {
  private val context = AnnotationConfigApplicationContext(WebConfiguration::class.java)
  private val client = WebTestClient.bindToApplicationContext(context).build()

  @AfterEach
  fun closeContext() {
    context.close()
  }

  @Test
  fun `query token authorizes suspend controller`() {
    client
      .get()
      .uri("/api?token=admin")
      .exchange()
      .expectStatus()
      .isOk
      .expectBody(String::class.java)
      .isEqualTo("security")
  }

  @Test
  fun `custom header authorizes suspend controller`() {
    client
      .get()
      .uri("/api")
      .header("x-auth", "admin")
      .exchange()
      .expectStatus()
      .isOk
      .expectBody(String::class.java)
      .isEqualTo("security")
  }

  @Test
  fun `method security denies a user without admin authority`() {
    client
      .get()
      .uri("/api?token=reader")
      .exchange()
      .expectStatus()
      .isForbidden
  }

  @Test
  fun `invalid token is unauthorized`() {
    client
      .get()
      .uri("/api?token=invalid")
      .exchange()
      .expectStatus()
      .isUnauthorized
  }

  @Configuration(proxyBeanMethods = false)
  @EnableWebFlux
  @Import(
    WebSecurityConfiguration::class,
    IndexController::class,
    UserProviderImpl::class
  )
  class WebConfiguration {
    @Bean
    fun tokenConverter(): HeaderOrQueryTokenAuthenticationConverter =
      HeaderOrQueryTokenAuthenticationConverter(
        SecurityProperties(
          authorizationHeader = SecurityProperties.AuthorizationHeader(name = "x-auth", prefix = ""),
          queryParameter = SecurityProperties.QueryParameter(enabled = true, name = "token")
        )
      )

    @Bean
    fun jwtDecoder(): ReactiveJwtDecoder =
      ReactiveJwtDecoder { token ->
        when (token) {
          "admin", "reader" -> {
            Mono.just(
              Jwt
                .withTokenValue(token)
                .header("alg", "RS512")
                .subject(token)
                .claim("roles", listOf(if (token == "admin") "ROLE_ADMIN" else "ROLE_READER"))
                .build()
            )
          }

          else -> {
            Mono.error(BadJwtException("Invalid token"))
          }
        }
      }
  }
}
