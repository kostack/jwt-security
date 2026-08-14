package io.github.kostack.jwt_security.extensions

inline fun <reified T> Map<String, Any>.getClaim(property: String): T {
  val claim =
    this[property]
      ?: throw IllegalArgumentException("$property claim is required but was null")

  return claim as? T
    ?: throw IllegalArgumentException(
      "$property claim expected ${T::class.simpleName} but was ${claim::class.simpleName}"
    )
}

inline fun <reified T> Map<String, Any>.getClaimOrNull(property: String): T? {
  val claim = this[property] ?: return null

  return this.getClaim<T>(property) as? T ?: throw IllegalArgumentException(
    "$property claim expected ${T::class.simpleName} but was ${claim::class.simpleName}"
  )
}
