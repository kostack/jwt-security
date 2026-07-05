package io.github.kostack.jwt_security.model

import io.github.kostack.jwt_security.service.JwtUser
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient

@Serializable
data class User(
  val id: String? = null,
  val username: String,
  @Transient
  val roles: List<String> = emptyList()
) : JwtUser {
  override val identity: String
    get() = username

  override fun toMap(): Map<String, Any> =
    mapOf(
      "id" to id!!,
      "username" to username,
      "roles" to roles
    )
}
