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

  @GetMapping("/.well-known/jwks.json")
  suspend fun jwksAction(): String =
    """{"keys":[{"kty":"RSA","e":"AQAB","use":"sig","kid":"local","alg":"RS512","n":"vy9cgMVzAwUejCjIahP_BfHEGbpk1AY0in6mtvmn7nHUmTPp6QnmDku4Jy9nA51Y4dz0uCq93dzI5vQuTYMMauwzwVDFKeLBaGN8VsNMo7RJaND56I14L4pI5c3vte0KXASC3sj720f5DazkrdZZMDlD83NUiz-Bu9L_mY7NtP_3o2EvXmoZ6y9UAYGPcsh4RIs3i7G2pfod-Cxz5AsjaLH6jZsRAz0X6QjPN-bTr2EcmPu3C_CD-Agocz89MEsiqEzPTVHlRvMQMIZLcocaWqZ-XuBrvMhNDbK1-QRANhy1b4DQQrXU2FWWGPNQ5c_0WNkLPJxVop8mNp9_gKbW58wg3J_FB4LmZCgDZGCneGReUYcFiH8CqXFBS4LBBn7boW9TjXYgFGqlYmXVFV1Z3d4NIdXm7WDN44_vKA3EVrh4ubfIUlFyGdj8FsNMouocAeoI5Op7Z7ng7zsiA3hfxa0QDBBS7Dvg6hlmVSUZV_I2PYfuZsU9hOxyZi_tz0fuOiBczYoI6ognLmgCq0fT1ti98TQ6YO1WLrj3Rh2i_91ZIDoEwyujBC4bkiFJV33IIwzTzA38jxZ4iRzeyoyuLFDMNAed7sp5HOO1Q9RJYdS7lYR_lAtDoR3GEqI7IPrN5ZCUzCpVebN9-ruell0txW4vldcJKNL122r_dtegVX0"}]}"""
}
