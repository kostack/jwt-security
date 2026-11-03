package io.github.kostack.jwt_security.converter

import kotlinx.coroutines.reactor.awaitSingleOrNull
import kotlinx.coroutines.reactor.mono
import org.springframework.core.convert.converter.Converter
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter
import reactor.core.publisher.Mono

open class JwtAuthenticationConverter(
  private val tokenFactory: JwtAuthenticationTokenFactory,
  private val delegate: ReactiveJwtAuthenticationConverter
) : Converter<Jwt, Mono<AbstractAuthenticationToken>> {
  override fun convert(jwt: Jwt): Mono<AbstractAuthenticationToken> =
    mono {
      val authentication = delegate.convert(jwt).awaitSingleOrNull() ?: return@mono null
      tokenFactory.create(jwt, authentication)
    }
}
