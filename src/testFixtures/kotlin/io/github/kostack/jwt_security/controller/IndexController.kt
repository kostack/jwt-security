package io.github.kostack.jwt_security.controller

import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class IndexController {
  @GetMapping("/api")
  @PreAuthorize("hasAuthority('ROLE_ADMIN')")
  suspend fun indexAction(): String = "security"
}
