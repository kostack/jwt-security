package io.github.kostack.jwt_security.service

interface JwtUserService {
  suspend fun findByIdentity(identity: String): JwtUser?

  suspend fun upsertFromPayload(payload: Map<String, Any>): JwtUser
}
