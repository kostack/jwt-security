package io.github.kostack.jwt_security.command

import com.github.freva.asciitable.AsciiTable
import io.github.kostack.jwt_security.encoder.JwtEncoder
import io.github.kostack.jwt_security.service.UserProvider
import kotlinx.coroutines.runBlocking
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.shell.core.command.annotation.Command
import org.springframework.shell.core.command.annotation.Option

class GenerateToken(
  private val userProvider: UserProvider,
  private val jwtEncoder: JwtEncoder
) {
  @Command(
    name = ["security:generate-token"],
    description = "Generate a JWT token for the given user identity"
  )
  fun generateToken(
    @Option(longName = "identity", shortName = 'u', required = true)
    identity: String
  ) = runBlocking {
    val user =
      userProvider.load(identity, emptyMap())
        ?: throw UsernameNotFoundException("User not found")
    val token = jwtEncoder.encode(user)
    val decoded = jwtEncoder.decode(token)

    println("\nGenerated Token:")
    println("=".repeat(50))
    println(token)
    println("=".repeat(50))

    val headersData =
      decoded.headers.entries
        .map { arrayOf(it.key, it.value.toString()) }
        .toTypedArray()

    println(
      "\nHeaders:\n" +
        AsciiTable.getTable(
          arrayOf("Key", "Value"),
          headersData
        )
    )

    val claimsData =
      decoded.claims.entries
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
