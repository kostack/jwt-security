package io.github.kostack.jwt_security.configuration

import io.github.kostack.jwt_security.authentication.AuthEntryPointJwt
import io.github.kostack.jwt_security.authentication.JwtServerAuthenticationConverter
import io.github.kostack.jwt_security.authentication.TokenAuthenticationManager
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.SecurityWebFiltersOrder
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.authentication.AuthenticationWebFilter
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository

@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
class WebSecurityConfiguration(
  private val tokenAuthenticationManager: TokenAuthenticationManager,
  private val jwtAuthenticationConverter: JwtServerAuthenticationConverter,
  private val authEntryPointJwt: AuthEntryPointJwt
) {
  @Bean
  fun securityWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
    val authenticationWebFilter =
      AuthenticationWebFilter(tokenAuthenticationManager).apply {
        setServerAuthenticationConverter(jwtAuthenticationConverter)
      }

    return http
      .exceptionHandling {
        it.authenticationEntryPoint(authEntryPointJwt)
      }.csrf { it.disable() }
      .formLogin { it.disable() }
      .httpBasic { it.disable() }
      .logout { it.disable() }
      .authorizeExchange {
        it
          .pathMatchers("/api/**")
          .authenticated()
          .anyExchange()
          .authenticated()
      }.addFilterAt(authenticationWebFilter, SecurityWebFiltersOrder.AUTHENTICATION)
      .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
      .build()
  }
}
