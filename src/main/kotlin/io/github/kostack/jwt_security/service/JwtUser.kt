package io.github.kostack.jwt_security.service

interface JwtUser {
  val identity: String

  fun toMap(): Map<String, Any>
}
