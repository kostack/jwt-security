package io.github.kostack.jwt_security.autoconfigure

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.SignatureAlgorithm
import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties(prefix = "jwt")
data class JwtProperties(
  var issuer: String = "",
  var expiration: Int = 3600,
  var privateKey: String = "",
  var signatureAlgorithm: String = "RS512",
  var publicKeys: Map<String, String> = emptyMap(),
  var authorizationHeaderOptions: AuthorizationHeaderOptions = AuthorizationHeaderOptions(),
  var queryParameterOptions: QueryParameterOptions = QueryParameterOptions()
) {
  data class AuthorizationHeaderOptions(
    var enabled: Boolean = false,
    var name: String = "",
    var prefix: String = ""
  )

  data class QueryParameterOptions(
    var enabled: Boolean = false,
    var name: String = "",
    var prefix: String = ""
  )

  fun getSignatureAlgorithm(): SignatureAlgorithm =
    when (signatureAlgorithm) {
      "RS512" -> Jwts.SIG.RS512
      "RS256" -> Jwts.SIG.RS256
      else -> throw IllegalArgumentException("Unsupported signature algorithm: $signatureAlgorithm")
    }
}
