package io.github.kostack.jwt_security.autoconfigure

import io.github.kostack.jwt_security.authentication.AuthEntryPointJwt
import io.github.kostack.jwt_security.authentication.JwtServerAuthenticationConverter
import io.github.kostack.jwt_security.authentication.TokenAuthenticationManager
import io.github.kostack.jwt_security.command.GenerateToken
import io.github.kostack.jwt_security.configuration.JwtProperties
import io.github.kostack.jwt_security.extractor.HeaderExtractor
import io.github.kostack.jwt_security.extractor.QueryParameterExtractor
import io.github.kostack.jwt_security.extractor.TokenExtractor
import io.github.kostack.jwt_security.service.JwtManager
import io.github.kostack.jwt_security.service.JwtUserService
import io.github.kostack.jwt_security.utils.IssuerKeyLocator
import io.github.kostack.jwt_security.utils.JwtKeyResolver
import org.springframework.beans.factory.ObjectProvider
import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.shell.standard.ShellMethod

@AutoConfiguration
@EnableConfigurationProperties(JwtProperties::class)
class JwtSecurityAutoConfiguration {
  @Bean
  @ConditionalOnMissingBean
  fun jwtKeyResolver(jwtProperties: JwtProperties): JwtKeyResolver = JwtKeyResolver(jwtProperties)

  @Bean
  @ConditionalOnMissingBean
  fun issuerKeyLocator(jwtKeyResolver: JwtKeyResolver): IssuerKeyLocator = IssuerKeyLocator(jwtKeyResolver)

  @Bean
  @ConditionalOnMissingBean
  fun jwtManager(
    jwtProperties: JwtProperties,
    jwtKeyResolver: JwtKeyResolver,
    issuerKeyLocator: IssuerKeyLocator
  ): JwtManager = JwtManager(jwtProperties, jwtKeyResolver, issuerKeyLocator)

  @Bean
  @ConditionalOnMissingBean
  fun authEntryPointJwt(): AuthEntryPointJwt = AuthEntryPointJwt()

  @Bean
  @ConditionalOnMissingBean
  fun headerExtractor(jwtProperties: JwtProperties): HeaderExtractor = HeaderExtractor(jwtProperties)

  @Bean
  @ConditionalOnMissingBean
  fun queryParameterExtractor(jwtProperties: JwtProperties): QueryParameterExtractor =
    QueryParameterExtractor(jwtProperties)

  @Bean
  @ConditionalOnMissingBean
  fun jwtServerAuthenticationConverter(tokenExtractors: List<TokenExtractor>): JwtServerAuthenticationConverter =
    JwtServerAuthenticationConverter(tokenExtractors)

  @Bean
  @ConditionalOnBean(JwtUserService::class)
  @ConditionalOnMissingBean
  fun tokenAuthenticationManager(
    jwtManager: JwtManager,
    userService: ObjectProvider<JwtUserService>
  ): TokenAuthenticationManager = TokenAuthenticationManager(jwtManager, userService.getObject())

  @Bean
  @ConditionalOnClass(ShellMethod::class)
  @ConditionalOnBean(JwtUserService::class)
  @ConditionalOnMissingBean
  fun generateToken(
    jwtManager: JwtManager,
    userService: ObjectProvider<JwtUserService>
  ): GenerateToken = GenerateToken(jwtManager, userService)
}
