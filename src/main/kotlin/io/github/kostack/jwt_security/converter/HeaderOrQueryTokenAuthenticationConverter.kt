package io.github.kostack.jwt_security.converter

import io.github.kostack.jwt_security.autoconfigure.SecurityProperties
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken
import org.springframework.security.oauth2.server.resource.web.server.authentication.ServerBearerTokenAuthenticationConverter
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono

open class HeaderOrQueryTokenAuthenticationConverter(
  properties: SecurityProperties
) : ServerAuthenticationConverter {
  private val headerEnabled = properties.authorizationHeader.enabled
  private val headerName = properties.authorizationHeader.name
  private val prefix = properties.authorizationHeader.prefix.trim()
  private val queryParameter = properties.queryParameter
  private val headerConverter =
    ServerBearerTokenAuthenticationConverter().apply {
      setBearerTokenHeaderName(headerName)
    }

  override fun convert(exchange: ServerWebExchange): Mono<Authentication> =
    Mono
      .defer { convertHeader(exchange) }
      .switchIfEmpty(
        Mono.defer {
          if (!queryParameter.enabled) return@defer Mono.empty()
          Mono
            .justOrEmpty(exchange.request.queryParams.getFirst(queryParameter.name))
            .filter { it.isNotBlank() }
            .map<Authentication> { BearerTokenAuthenticationToken(it) }
        }
      )

  private fun convertHeader(exchange: ServerWebExchange): Mono<Authentication> {
    if (!headerEnabled) return Mono.empty()
    val value = exchange.request.headers.getFirst(headerName) ?: return Mono.empty()
    val normalized =
      if (prefix.isEmpty()) {
        "Bearer $value"
      } else {
        if (!value.startsWith(prefix, ignoreCase = true)) return Mono.empty()
        "Bearer" + value.substring(prefix.length)
      }
    val normalizedExchange =
      exchange
        .mutate()
        .request { request ->
          request.headers { it.set(headerName, normalized) }
        }.build()
    return headerConverter.convert(normalizedExchange)
  }
}
