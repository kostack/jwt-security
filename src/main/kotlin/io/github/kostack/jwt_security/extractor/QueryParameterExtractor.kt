package io.github.kostack.jwt_security.extractor

import io.github.kostack.jwt_security.configuration.JwtProperties
import org.springframework.http.server.reactive.ServerHttpRequest
import org.springframework.stereotype.Component

@Component
class QueryParameterExtractor(
  private val jwtProperties: JwtProperties
) : TokenExtractor {
  override fun extract(request: ServerHttpRequest): String? =
    jwtProperties.queryParameterOptions
      .takeIf { it.enabled }
      ?.let { request.queryParams.getFirst(it.name) }
}
