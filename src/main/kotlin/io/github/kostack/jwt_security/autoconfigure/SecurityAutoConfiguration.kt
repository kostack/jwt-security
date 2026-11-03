package io.github.kostack.jwt_security.autoconfigure

import io.github.kostack.jwt_security.converter.HeaderOrQueryTokenAuthenticationConverter
import io.github.kostack.jwt_security.converter.JwtAuthenticationConverter
import io.github.kostack.jwt_security.converter.JwtAuthenticationTokenFactory
import io.github.kostack.jwt_security.converter.JwtUserAuthenticationTokenFactory
import io.github.kostack.jwt_security.dto.JwtUser
import io.github.kostack.jwt_security.encoder.JwtClaimsValidator
import io.github.kostack.jwt_security.encoder.JwtEncoder
import io.github.kostack.jwt_security.encoder.JwtEncoderImpl
import io.github.kostack.jwt_security.encoder.RequiredJwtClaimsValidator
import io.github.kostack.jwt_security.service.AuthEntryPointJwt
import io.github.kostack.jwt_security.service.JwtKeyResolver
import io.github.kostack.jwt_security.service.UserProvider
import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtGrantedAuthoritiesConverterAdapter
import java.time.Clock

@AutoConfiguration
@EnableConfigurationProperties(SecurityProperties::class)
class SecurityAutoConfiguration {
  @Bean
  @ConditionalOnMissingBean
  fun clock(): Clock = Clock.systemUTC()

  @Bean
  @ConditionalOnMissingBean(AuthEntryPointJwt::class)
  fun authEntryPointJwt(): AuthEntryPointJwt = AuthEntryPointJwt()

  @Bean
  @ConditionalOnMissingBean(JwtKeyResolver::class)
  fun jwtKeyResolver(properties: SecurityProperties): JwtKeyResolver = JwtKeyResolver(properties)

  @Bean
  @ConditionalOnMissingBean(JwtEncoder::class)
  fun jwtEncoder(
    keyResolver: JwtKeyResolver,
    properties: SecurityProperties,
    clock: Clock,
    claimsValidator: JwtClaimsValidator
  ): JwtEncoder = JwtEncoderImpl(keyResolver, properties, clock, claimsValidator)

  @Bean
  @ConditionalOnMissingBean(HeaderOrQueryTokenAuthenticationConverter::class)
  fun headerOrQueryTokenAuthenticationConverter(
    properties: SecurityProperties
  ): HeaderOrQueryTokenAuthenticationConverter = HeaderOrQueryTokenAuthenticationConverter(properties)

  @Bean
  @ConditionalOnMissingBean(JwtClaimsValidator::class)
  fun jwtClaimsValidator(properties: SecurityProperties): JwtClaimsValidator = RequiredJwtClaimsValidator(properties)

  @Bean
  @ConditionalOnMissingBean(JwtAuthenticationTokenFactory::class)
  fun jwtAuthenticationTokenFactory(userProvider: UserProvider): JwtAuthenticationTokenFactory =
    JwtUserAuthenticationTokenFactory(userProvider)

  @Bean
  @ConditionalOnMissingBean(JwtAuthenticationConverter::class)
  fun jwtAuthenticationConverter(
    tokenFactory: JwtAuthenticationTokenFactory,
    delegate: ReactiveJwtAuthenticationConverter
  ): JwtAuthenticationConverter = JwtAuthenticationConverter(tokenFactory, delegate)

  @Bean
  @ConditionalOnMissingBean(ReactiveJwtAuthenticationConverter::class)
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
  @ConditionalOnMissingBean(ReactiveJwtDecoder::class)
  fun jwtDecoder(encoder: JwtEncoder): ReactiveJwtDecoder = encoder.decoder()

  @Bean
  @ConditionalOnMissingBean(UserProvider::class)
  fun userProvider(): UserProvider =
    object : UserProvider {
      override suspend fun load(
        identity: String,
        claims: Map<String, Any>
      ): JwtUser? {
        TODO("Not yet implemented")
      }
    }
}
