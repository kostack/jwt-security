package io.github.kostack.jwt_security.extractor

import org.springframework.http.server.reactive.ServerHttpRequest

interface TokenExtractor {
  fun extract(request: ServerHttpRequest): String?
}
