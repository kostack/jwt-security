package io.github.kostack.jwt_security.controller

import io.github.kostack.jwt_security.model.User
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class IndexController {
  @GetMapping("/api")
  @PreAuthorize("hasRole('ADMIN')")
  suspend fun indexAction(
    @AuthenticationPrincipal user: User
  ): User = user
}
