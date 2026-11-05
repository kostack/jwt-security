package io.github.kostack.jwt_security.jwks

import io.github.kostack.jwt_security.autoconfigure.SecurityAutoConfiguration
import io.github.kostack.jwt_security.service.UserProvider
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.boot.autoconfigure.AutoConfigurations
import org.springframework.boot.test.context.runner.ApplicationContextRunner
import java.util.function.Supplier

class JwksAutoConfigurationTest {
  private val contextRunner =
    ApplicationContextRunner()
      .withConfiguration(AutoConfigurations.of(SecurityAutoConfiguration::class.java))
      .withBean(UserProvider::class.java, Supplier { mockk<UserProvider>() })

  @Test
  fun `registers the default JWKS service without component scanning`() {
    contextRunner.run { context ->
      assertThat(context).hasSingleBean(JwksService::class.java)
      assertThat(context.getBean(JwksService::class.java)).isInstanceOf(JwksServiceImpl::class.java)
    }
  }

  @Test
  fun `backs off when an application supplies its own JWKS service`() {
    val custom =
      object : JwksService {
        override fun publicKeys(): Map<String, Any> = mapOf("keys" to emptyList<Any>())
      }
    contextRunner.withBean(JwksService::class.java, Supplier { custom }).run { context ->
      assertThat(context).hasSingleBean(JwksService::class.java)
      assertThat(context.getBean(JwksService::class.java)).isSameAs(custom)
    }
  }
}
