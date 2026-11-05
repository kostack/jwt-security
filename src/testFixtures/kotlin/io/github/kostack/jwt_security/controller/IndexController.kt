package io.github.kostack.jwt_security.controller

import io.github.kostack.jwt_security.jwks.JwksService
import io.github.kostack.jwt_security.model.User
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class IndexController(
  private val jwksService: JwksService
) {
  @GetMapping("/api")
  @PreAuthorize("hasRole('ADMIN')")
  suspend fun indexAction(
    @AuthenticationPrincipal user: User
  ): User = user

  @GetMapping("/.well-known/jwks.json")
  suspend fun jwksAction(): Map<String, Any> = jwksService.publicKeys()
}
