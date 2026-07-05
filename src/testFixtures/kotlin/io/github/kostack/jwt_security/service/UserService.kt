package io.github.kostack.jwt_security.service

import io.github.kostack.jwt_security.model.User
import org.springframework.stereotype.Service

@Service
class UserService : JwtUserService {
  override suspend fun findByIdentity(identity: String): JwtUser = User(identity, "admin", listOf("ROLE_ADMIN"))

  override suspend fun upsertFromPayload(payload: Map<String, Any>): JwtUser = findByIdentity(payload["sub"].toString())
}
