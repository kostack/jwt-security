package io.github.kostack.jwt_security.converter

import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.jwt.Jwt

fun interface JwtAuthenticationTokenFactory {
  suspend fun create(
    jwt: Jwt,
    authentication: Authentication
  ): AbstractAuthenticationToken
}
