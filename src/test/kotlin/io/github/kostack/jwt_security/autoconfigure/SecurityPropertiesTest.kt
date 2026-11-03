package io.github.kostack.jwt_security.autoconfigure

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.boot.context.properties.bind.Bindable
import org.springframework.boot.context.properties.bind.Binder
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource
import org.springframework.boot.test.context.runner.ApplicationContextRunner
import org.springframework.context.annotation.Configuration

class SecurityPropertiesTest {
  private val contextRunner =
    ApplicationContextRunner().withUserConfiguration(PropertiesConfiguration::class.java)

  @Test
  fun `binds custom header and nested properties`() {
    contextRunner
      .withPropertyValues(
        "kostack-security.authorization-header.name=x-auth",
        "kostack-security.authorization-header.prefix=",
        "kostack-security.issuer.name=https://issuer.example",
        "kostack-security.issuer.expiration-time=900",
        "kostack-security.public-keys.custom=public-key",
        "kostack-security.authorities-claim=permissions",
        "kostack-security.authority-prefix=ROLE_",
        "kostack-security.query-parameter.enabled=true",
        "kostack-security.query-parameter.name=token"
      ).run { context ->
        assertThat(context).hasNotFailed()
        val properties = context.getBean(SecurityProperties::class.java)
        assertThat(properties.authorizationHeader.name).isEqualTo("x-auth")
        assertThat(properties.authorizationHeader.prefix).isEmpty()
        assertThat(properties.authorizationHeader.enabled).isTrue()
        assertThat(properties.issuer.name).isEqualTo("https://issuer.example")
        assertThat(properties.issuer.expirationTime).isEqualTo(900)
        assertThat(properties.issuer.kid).isEqualTo("local")
        assertThat(properties.publicKeys).containsEntry("custom", "public-key")
        assertThat(properties.authoritiesClaim).isEqualTo("permissions")
        assertThat(properties.authorityPrefix).isEqualTo("ROLE_")
        assertThat(properties.queryParameter.enabled).isTrue()
        assertThat(properties.queryParameter.name).isEqualTo("token")
      }
  }

  @Test
  fun `binds properties onto an existing instance`() {
    val properties = SecurityProperties()
    val source =
      MapConfigurationPropertySource(
        mapOf(
          "kostack-security.authorization-header.name" to "x-auth",
          "kostack-security.authorization-header.prefix" to "",
          "kostack-security.issuer.name" to "https://issuer.example",
          "kostack-security.public-keys.custom" to "public-key"
        )
      )

    val bound = Binder(source).bind("kostack-security", Bindable.ofInstance(properties)).get()

    assertThat(bound).isSameAs(properties)
    assertThat(bound.authorizationHeader.name).isEqualTo("x-auth")
    assertThat(bound.authorizationHeader.prefix).isEmpty()
    assertThat(bound.issuer.name).isEqualTo("https://issuer.example")
    assertThat(bound.publicKeys).containsEntry("custom", "public-key")
  }

  @Test
  fun `retains defaults when no properties are supplied`() {
    contextRunner.run { context ->
      assertThat(context).hasNotFailed()
      assertThat(context.getBean(SecurityProperties::class.java)).isEqualTo(SecurityProperties())
    }
  }

  @Configuration(proxyBeanMethods = false)
  @EnableConfigurationProperties(SecurityProperties::class)
  class PropertiesConfiguration
}
