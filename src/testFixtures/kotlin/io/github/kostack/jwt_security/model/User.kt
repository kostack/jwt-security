package io.github.kostack.jwt_security.model

import io.github.kostack.jwt_security.dto.JwtUser
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient

@Serializable
data class User(
  val username: String,
  @Transient
  val roles: List<String> = emptyList()
) : JwtUser {
  override val identity: String
    get() = username

  override fun claims(): Map<String, Any> =
    mapOf(
      "username" to username,
      "roles" to roles
    )
}
