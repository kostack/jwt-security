package io.github.kostack.jwt_security.dto

interface JwtUser {
  val identity: String

  fun claims(): Map<String, Any>
}
