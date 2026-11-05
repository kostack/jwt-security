package io.github.kostack.jwt_security.service

import io.github.kostack.jwt_security.autoconfigure.SecurityProperties
import io.github.kostack.jwt_security.converter.JwtAuthenticationConverter
import org.springframework.security.authentication.ReactiveAuthenticationManager
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerReactiveAuthenticationManagerResolver
import org.springframework.security.oauth2.server.resource.authentication.JwtReactiveAuthenticationManager
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono

class TrustedIssuerAuthenticationManagerResolver(
  properties: SecurityProperties,
  decoder: ReactiveJwtDecoder,
  converter: JwtAuthenticationConverter
) : ReactiveAuthenticationManagerResolver<ServerWebExchange> {
  private val delegate: JwtIssuerReactiveAuthenticationManagerResolver

  init {
    require(properties.trustedIssuers.isNotEmpty()) { "At least one trusted issuer is required" }
    val managers = mutableMapOf<String, ReactiveAuthenticationManager>()
    properties.trustedIssuers.values.forEach { issuer ->
      managers[issuer.issuer] =
        JwtReactiveAuthenticationManager(decoder).apply {
          setJwtAuthenticationConverter(converter)
        }
    }
    delegate =
      JwtIssuerReactiveAuthenticationManagerResolver(
        { issuer -> Mono.justOrEmpty(managers[issuer]) }
      )
  }

  override fun resolve(context: ServerWebExchange): Mono<ReactiveAuthenticationManager> = delegate.resolve(context)
}
