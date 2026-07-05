package io.github.kostack.jwt_security.authentication

import io.github.kostack.jwt_security.service.JwtManager
import io.github.kostack.jwt_security.service.JwtUserService
import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jws
import kotlinx.coroutines.reactor.mono
import org.slf4j.LoggerFactory
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.ReactiveAuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.SimpleGrantedAuthority
import reactor.core.publisher.Mono
import kotlin.collections.map

class TokenAuthenticationManager(
  private val jwtManager: JwtManager,
  private val userService: JwtUserService
) : ReactiveAuthenticationManager {
  override fun authenticate(authentication: Authentication): Mono<Authentication> =
    mono {
      val authToken = authentication.credentials?.toString() ?: throw BadCredentialsException("Missing token")

      try {
        if (!jwtManager.validateJwtToken(authToken)) {
          log.info("JWT token validation failed")
          throw BadCredentialsException("Invalid token")
        }

        val claims: Jws<Claims> = jwtManager.getClaims(authToken)
        val payload = claims.payload

        val username =
          payload.subject
            ?: throw BadCredentialsException("Invalid token payload")

        val roles =
          payload["roles"] as List<*>?
            ?: throw BadCredentialsException("Invalid user roles payload")

        if (roles.any { it !is String }) {
          throw BadCredentialsException("Invalid roles format in JWT claims")
        }

        val authorities = roles.map { SimpleGrantedAuthority(it as String) }
        val user = userService.upsertFromPayload(payload)

        log.debug("Authenticated user: {}, with roles: {}", username, authorities)
        return@mono UsernamePasswordAuthenticationToken(user, null, authorities)
      } catch (e: Exception) {
        if (e is BadCredentialsException) {
          throw e
        } else {
          log.error("Error during JWT authentication: {}", e.message, e)
          throw BadCredentialsException("Error during authentication")
        }
      }
    }

  companion object {
    private val log = LoggerFactory.getLogger(TokenAuthenticationManager::class.java)
  }
}
