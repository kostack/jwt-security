package io.github.kostack.jwt_security.extractor

import io.github.kostack.jwt_security.autoconfigure.JwtProperties
import org.springframework.http.server.reactive.ServerHttpRequest

class HeaderExtractor(
  private val jwtProperties: JwtProperties
) : TokenExtractor {
  override fun extract(request: ServerHttpRequest): String? {
    val options =
      jwtProperties.authorizationHeaderOptions
        .takeIf { it.enabled }
        ?: return null

    val header = request.headers.getFirst(options.name) ?: return null
    return header
      .takeIf { it.startsWith(options.prefix) }
      ?.substring(options.prefix.length + 1)
  }
}
