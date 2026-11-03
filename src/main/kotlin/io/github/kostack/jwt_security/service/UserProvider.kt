package io.github.kostack.jwt_security.service

import io.github.kostack.jwt_security.dto.JwtUser

interface UserProvider {
  suspend fun load(
    identity: String,
    claims: Map<String, Any>
  ): JwtUser?
}
