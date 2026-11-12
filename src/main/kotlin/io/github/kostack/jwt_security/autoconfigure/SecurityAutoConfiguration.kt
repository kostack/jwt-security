package io.github.kostack.jwt_security.autoconfigure

import io.github.kostack.jwt_security.command.GenerateToken
import io.github.kostack.jwt_security.converter.HeaderOrQueryTokenAuthenticationConverter
import io.github.kostack.jwt_security.converter.JwtAuthenticationConverter
import io.github.kostack.jwt_security.converter.JwtAuthenticationTokenFactory
import io.github.kostack.jwt_security.converter.JwtUserAuthenticationTokenFactory
import io.github.kostack.jwt_security.encoder.JwtClaimsValidator
import io.github.kostack.jwt_security.encoder.JwtEncoder
import io.github.kostack.jwt_security.encoder.JwtEncoderImpl
import io.github.kostack.jwt_security.encoder.RequiredJwtClaimsValidator
import io.github.kostack.jwt_security.jwks.JwksService
import io.github.kostack.jwt_security.jwks.JwksServiceImpl
import io.github.kostack.jwt_security.service.AuthEntryPointJwt
import io.github.kostack.jwt_security.service.JwtKeyResolver
import io.github.kostack.jwt_security.service.TrustedIssuerAuthenticationManagerResolver
import io.github.kostack.jwt_security.service.UserProvider
import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Conditional
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtGrantedAuthoritiesConverterAdapter
import org.springframework.web.server.ServerWebExchange
import java.time.Clock

@AutoConfiguration
@EnableConfigurationProperties(SecurityProperties::class)
class SecurityAutoConfiguration {
  @Bean
  @ConditionalOnMissingBean
  fun clock(): Clock = Clock.systemUTC()

  @Bean
  @ConditionalOnMissingBean
  fun authEntryPointJwt(): AuthEntryPointJwt = AuthEntryPointJwt()

  @Bean
  @ConditionalOnMissingBean
  fun jwtKeyResolver(properties: SecurityProperties): JwtKeyResolver = JwtKeyResolver(properties)

  @Bean
  @ConditionalOnMissingBean
  fun jwksService(
    properties: SecurityProperties,
    keyResolver: JwtKeyResolver
  ): JwksService = JwksServiceImpl(properties, keyResolver)

  @Bean
  @ConditionalOnMissingBean
  fun jwtEncoder(
    keyResolver: JwtKeyResolver,
    properties: SecurityProperties,
    clock: Clock,
    claimsValidator: JwtClaimsValidator
  ): JwtEncoder = JwtEncoderImpl(keyResolver, properties, clock, claimsValidator)

  @Bean
  @ConditionalOnMissingBean
  fun headerOrQueryTokenAuthenticationConverter(
    properties: SecurityProperties
  ): HeaderOrQueryTokenAuthenticationConverter = HeaderOrQueryTokenAuthenticationConverter(properties)

  @Bean
  @ConditionalOnMissingBean
  fun jwtClaimsValidator(properties: SecurityProperties): JwtClaimsValidator = RequiredJwtClaimsValidator(properties)

  @Bean
  @ConditionalOnBean(UserProvider::class)
  @ConditionalOnMissingBean
  fun jwtAuthenticationTokenFactory(userProvider: UserProvider): JwtAuthenticationTokenFactory =
    JwtUserAuthenticationTokenFactory(userProvider)

  @Bean
  @ConditionalOnMissingBean
  fun jwtAuthenticationConverter(
    tokenFactory: JwtAuthenticationTokenFactory,
    delegate: ReactiveJwtAuthenticationConverter
  ): JwtAuthenticationConverter = JwtAuthenticationConverter(tokenFactory, delegate)

  @Bean
  @ConditionalOnMissingBean
  fun reactiveJwtAuthenticationConverter(properties: SecurityProperties): ReactiveJwtAuthenticationConverter {
    val authorities =
      JwtGrantedAuthoritiesConverter().apply {
        setAuthoritiesClaimName(properties.authoritiesClaim)
        setAuthorityPrefix(properties.authorityPrefix)
      }
    return ReactiveJwtAuthenticationConverter().apply {
      setJwtGrantedAuthoritiesConverter(
        ReactiveJwtGrantedAuthoritiesConverterAdapter(authorities)
      )
    }
  }

  @Bean
  @ConditionalOnMissingBean
  fun jwtDecoder(encoder: JwtEncoder): ReactiveJwtDecoder = encoder.decoder()

  @Bean
  @ConditionalOnMissingBean(ReactiveAuthenticationManagerResolver::class)
  @Conditional(TrustedIssuersConfiguredCondition::class)
  fun trustedIssuerAuthenticationManagerResolver(
    properties: SecurityProperties,
    decoder: ReactiveJwtDecoder,
    converter: JwtAuthenticationConverter
  ): ReactiveAuthenticationManagerResolver<ServerWebExchange> =
    TrustedIssuerAuthenticationManagerResolver(properties, decoder, converter)

  @Configuration(proxyBeanMethods = false)
  @ConditionalOnClass(name = ["org.springframework.shell.core.command.Command"])
  class ShellConfiguration {
    @Bean
    @ConditionalOnBean(UserProvider::class)
    @ConditionalOnMissingBean
    fun generateToken(
      userProvider: UserProvider,
      jwtEncoder: JwtEncoder
    ): GenerateToken = GenerateToken(userProvider, jwtEncoder)
  }
}
