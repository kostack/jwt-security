package io.github.kostack.jwt_security.autoconfigure

import io.github.kostack.jwt_security.converter.HeaderOrQueryTokenAuthenticationConverter
import io.github.kostack.jwt_security.converter.JwtAuthenticationConverter
import io.github.kostack.jwt_security.service.AuthEntryPointJwt
import org.springframework.beans.factory.ObjectProvider
import org.springframework.boot.autoconfigure.ImportAutoConfiguration
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository
import org.springframework.web.server.ServerWebExchange

@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
@ImportAutoConfiguration(SecurityAutoConfiguration::class)
internal class WebSecurityConfiguration(
  val converter: JwtAuthenticationConverter,
  val authEntryPointJwt: AuthEntryPointJwt,
  val resolvers: ObjectProvider<ReactiveAuthenticationManagerResolver<ServerWebExchange>>
) {
  @Bean
  fun securityWebFilterChain(
    http: ServerHttpSecurity,
    tokenConverter: HeaderOrQueryTokenAuthenticationConverter
  ): SecurityWebFilterChain =
    http
      .exceptionHandling { it.authenticationEntryPoint(authEntryPointJwt) }
      .csrf { it.disable() }
      .formLogin { it.disable() }
      .httpBasic { it.disable() }
      .logout { it.disable() }
      .authorizeExchange {
        it
          .pathMatchers("/api/**")
          .authenticated()
          .anyExchange()
          .authenticated()
      }.securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
      .oauth2ResourceServer {
        it.bearerTokenConverter(tokenConverter)
        it.authenticationEntryPoint(authEntryPointJwt)
        val resolver = resolvers.ifAvailable
        if (resolver != null) {
          it.authenticationManagerResolver(resolver)
        } else {
          it.jwt { jwt -> jwt.jwtAuthenticationConverter(converter) }
        }
      }.build()
}
