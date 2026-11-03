package io.github.kostack.jwt_security.autoconfigure

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm

@ConfigurationProperties("kostack-security")
data class SecurityProperties(
  var issuer: Issuer = Issuer(),
  var publicKeys: Map<String, String> = mapOf("local" to ""),
  var authoritiesClaim: String = "roles",
  var authorityPrefix: String = "",
  var authorizationHeader: AuthorizationHeader = AuthorizationHeader(),
  var queryParameter: QueryParameter = QueryParameter()
) {
  data class Issuer(
    var kid: String = "local",
    var name: String = "https://issuer.local",
    var audience: String = "",
    var privateKey: String = "",
    var algorithmSignature: SignatureAlgorithm = SignatureAlgorithm.RS512,
    var expirationTime: Long = 3600
  )

  data class AuthorizationHeader(
    var enabled: Boolean = true,
    var name: String = "Authorization",
    var prefix: String = "Bearer"
  )

  data class QueryParameter(
    var enabled: Boolean = false,
    var name: String = ""
  )
}
