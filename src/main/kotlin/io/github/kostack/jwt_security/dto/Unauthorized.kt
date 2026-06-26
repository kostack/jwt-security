package io.github.kostack.jwt_security.dto

import kotlinx.serialization.Serializable

@Serializable
data class Unauthorized(
  val status: Int,
  val error: String = "Unauthorized",
  val message: String = "Authentication token was either missing or invalid.",
  val path: String
)
