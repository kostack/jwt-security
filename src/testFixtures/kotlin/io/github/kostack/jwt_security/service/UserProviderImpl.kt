package io.github.kostack.jwt_security.service

import io.github.kostack.jwt_security.dto.JwtUser
import io.github.kostack.jwt_security.model.User
import org.springframework.stereotype.Service

@Service
class UserProviderImpl : UserProvider {
  override suspend fun load(
    identity: String,
    claims: Map<String, Any>
  ): JwtUser? = User(identity, listOf("ROLE_ADMIN"))
}
