package io.github.kostack.jwt_security.command

import com.github.freva.asciitable.AsciiTable
import io.github.kostack.jwt_security.service.JwtManager
import io.github.kostack.jwt_security.service.JwtUserService
import kotlinx.coroutines.runBlocking
import org.springframework.shell.command.annotation.Option
import org.springframework.shell.standard.ShellComponent
import org.springframework.shell.standard.ShellMethod

@ShellComponent
class GenerateToken(
  private val jwtManager: JwtManager,
  private val userService: JwtUserService
) {
  @ShellMethod(
    key = ["security:generate-token"],
    value = "Generate a JWT token for the given user identity"
  )
  fun generateToken(
    @Option(longNames = ["identity"], shortNames = ['u'], required = true)
    identity: String
  ) = runBlocking {
    val user = userService.findByIdentity(identity)
    if (user == null) {
      println("User not found: $identity")
      return@runBlocking
    }

    val token = jwtManager.generateToken(user)
    val claims = jwtManager.getClaims(token).payload

    println("\nGenerated Token:")
    println("=".repeat(50))
    println(token)
    println("=".repeat(50))

    val claimsData =
      claims.entries
        .map { arrayOf(it.key, it.value.toString()) }
        .toTypedArray()

    println(
      "\nClaims:\n" +
        AsciiTable.getTable(
          arrayOf("Key", "Value"),
          claimsData
        )
    )
  }
}
