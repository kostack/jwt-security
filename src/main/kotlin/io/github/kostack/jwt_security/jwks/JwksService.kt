package io.github.kostack.jwt_security.jwks

interface JwksService {
  fun publicKeys(): Map<String, Any>
}
