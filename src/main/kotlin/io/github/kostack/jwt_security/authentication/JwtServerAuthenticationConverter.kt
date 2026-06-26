package io.github.kostack.jwt_security.authentication

import io.github.kostack.jwt_security.extractor.TokenExtractor
import kotlinx.coroutines.reactor.mono
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono

@Component
class JwtServerAuthenticationConverter(
  private val tokenExtractors: List<TokenExtractor>
) : ServerAuthenticationConverter {
  override fun convert(exchange: ServerWebExchange): Mono<Authentication> =
    mono {
      return@mono tokenExtractors
        .firstNotNullOfOrNull { it.extract(exchange.request) }
        ?.let { token ->
          UsernamePasswordAuthenticationToken(token, token)
        }
    }
}
