package io.github.kostack.jwt_security

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.context.annotation.Bean
import org.springframework.shell.core.autoconfigure.TerminalCustomizer

@SpringBootApplication
class TestApplication {
  @Bean
  fun terminalCustomizer(): TerminalCustomizer = TerminalCustomizer { it.dumb(true) }
}

fun main(args: Array<String>) {
  runApplication<TestApplication>(*args) {
    setDefaultProperties(TestJwtKeys.properties)
  }
}
