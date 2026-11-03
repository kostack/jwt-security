package io.github.kostack.jwt_security.converter

import io.github.kostack.jwt_security.service.UserProvider
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.jwt.Jwt

class JwtUserAuthenticationTokenFactory(
  private val userProvider: UserProvider
) : JwtAuthenticationTokenFactory {
  override suspend fun create(
    jwt: Jwt,
    authentication: Authentication
  ): UsernamePasswordAuthenticationToken {
    val subject =
      jwt.subject?.takeIf { it.isNotBlank() }
        ?: throw BadCredentialsException("Missing subject")
    val user =
      userProvider.load(subject, jwt.claims)
        ?: throw BadCredentialsException("User not found")
    return UsernamePasswordAuthenticationToken.authenticated(
      user,
      null,
      authentication.authorities
    )
  }
}
