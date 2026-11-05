package io.github.kostack.jwt_security.command

import io.github.kostack.jwt_security.autoconfigure.SecurityAutoConfiguration
import io.github.kostack.jwt_security.converter.JwtAuthenticationTokenFactory
import io.github.kostack.jwt_security.service.UserProvider
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.boot.autoconfigure.AutoConfigurations
import org.springframework.boot.test.context.FilteredClassLoader
import org.springframework.boot.test.context.runner.ApplicationContextRunner
import org.springframework.shell.core.command.Command
import java.util.function.Supplier

class GenerateTokenAutoConfigurationTest {
  private val contextRunner =
    ApplicationContextRunner()
      .withConfiguration(AutoConfigurations.of(SecurityAutoConfiguration::class.java))

  @Test
  fun `registers the token command without component scanning`() {
    contextRunner.withBean(UserProvider::class.java, Supplier { mockk<UserProvider>() }).run { context ->
      assertThat(context).hasSingleBean(GenerateToken::class.java)
    }
  }

  @Test
  fun `backs off when an application supplies its own token command`() {
    val custom = GenerateToken(mockk(), mockk())
    contextRunner
      .withBean(UserProvider::class.java, Supplier { mockk<UserProvider>() })
      .withBean(GenerateToken::class.java, Supplier { custom })
      .run { context ->
        assertThat(context).hasSingleBean(GenerateToken::class.java)
        assertThat(context.getBean(GenerateToken::class.java)).isSameAs(custom)
      }
  }

  @Test
  fun `does not register a token command without a user provider`() {
    contextRunner
      .withBean(JwtAuthenticationTokenFactory::class.java, Supplier { mockk<JwtAuthenticationTokenFactory>() })
      .run { context ->
        assertThat(context).hasNotFailed()
        assertThat(context).doesNotHaveBean(UserProvider::class.java)
        assertThat(context).doesNotHaveBean(GenerateToken::class.java)
      }
  }

  @Test
  fun `does not register a token command when Spring Shell is absent`() {
    contextRunner
      .withClassLoader(FilteredClassLoader(Command::class.java))
      .withBean(UserProvider::class.java, Supplier { mockk<UserProvider>() })
      .run { context ->
        assertThat(context).hasNotFailed()
        assertThat(context).doesNotHaveBean(GenerateToken::class.java)
      }
  }
}
