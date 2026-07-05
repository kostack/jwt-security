package io.github.kostack.jwt_security.autoconfigure

import io.github.kostack.jwt_security.authentication.AuthEntryPointJwt
import io.github.kostack.jwt_security.authentication.JwtServerAuthenticationConverter
import io.github.kostack.jwt_security.authentication.TokenAuthenticationManager
import io.github.kostack.jwt_security.command.GenerateToken
import io.github.kostack.jwt_security.configuration.JwtProperties
import io.github.kostack.jwt_security.extractor.HeaderExtractor
import io.github.kostack.jwt_security.extractor.QueryParameterExtractor
import io.github.kostack.jwt_security.service.JwtManager
import io.github.kostack.jwt_security.service.JwtUser
import io.github.kostack.jwt_security.service.JwtUserService
import io.github.kostack.jwt_security.utils.IssuerKeyLocator
import io.github.kostack.jwt_security.utils.JwtKeyResolver
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.boot.autoconfigure.AutoConfigurations
import org.springframework.boot.test.context.runner.ApplicationContextRunner

class JwtSecurityAutoConfigurationTest {
  private val contextRunner =
    ApplicationContextRunner()
      .withConfiguration(AutoConfigurations.of(JwtSecurityAutoConfiguration::class.java))
      .withPropertyValues(
        "jwt.issuer=local",
        "jwt.private-key=src/testFixtures/resources/jwt/private.pem",
        "jwt.public-keys.local=src/testFixtures/resources/jwt/public.pem",
        "jwt.authorization-header-options.enabled=true",
        "jwt.authorization-header-options.name=Authorization",
        "jwt.authorization-header-options.prefix=Bearer",
        "jwt.query-parameter-options.enabled=true",
        "jwt.query-parameter-options.name=bearer"
      )

  @Test
  fun `auto configures jwt security beans`() {
    contextRunner
      .withBean(JwtUserService::class.java, { TestJwtUserService() })
      .run { context ->
        assertThat(context).hasSingleBean(JwtProperties::class.java)
        assertThat(context).hasSingleBean(JwtKeyResolver::class.java)
        assertThat(context).hasSingleBean(IssuerKeyLocator::class.java)
        assertThat(context).hasSingleBean(JwtManager::class.java)
        assertThat(context).hasSingleBean(AuthEntryPointJwt::class.java)
        assertThat(context).hasSingleBean(HeaderExtractor::class.java)
        assertThat(context).hasSingleBean(QueryParameterExtractor::class.java)
        assertThat(context).hasSingleBean(JwtServerAuthenticationConverter::class.java)
        assertThat(context).hasSingleBean(TokenAuthenticationManager::class.java)
        assertThat(context).hasSingleBean(GenerateToken::class.java)
      }
  }

  @Test
  fun `backs off when jwt manager is provided`() {
    val jwtProperties = JwtProperties()
    val jwtKeyResolver = JwtKeyResolver(jwtProperties)
    val customJwtManager = JwtManager(jwtProperties, jwtKeyResolver, IssuerKeyLocator(jwtKeyResolver))

    contextRunner
      .withBean(JwtUserService::class.java, { TestJwtUserService() })
      .withBean(JwtManager::class.java, { customJwtManager })
      .run { context ->
        assertThat(context).hasSingleBean(JwtManager::class.java)
        assertThat(context.getBean(JwtManager::class.java)).isSameAs(customJwtManager)
      }
  }

  private class TestJwtUserService : JwtUserService {
    override suspend fun findByIdentity(identity: String): JwtUser? = null

    override suspend fun upsertFromPayload(payload: Map<String, Any>): JwtUser = throw UnsupportedOperationException()
  }
}
