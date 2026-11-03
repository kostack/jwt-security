package io.github.kostack.jwt_security.encoder

import org.springframework.security.oauth2.core.OAuth2TokenValidator
import org.springframework.security.oauth2.jwt.Jwt

fun interface JwtClaimsValidator : OAuth2TokenValidator<Jwt>
