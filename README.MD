# JWT Security

A Kotlin library for RSA-signed JWTs and reactive Spring Security authentication in WebFlux applications.

## Features

- RSA token signing with RS256, RS384, or RS512.
- Coroutine APIs for encoding and decoding, plus a reactive JWT decoder.
- Header and optional query-parameter token extraction.
- Application-defined user loading and authentication principals.
- Public-key selection by JWT `kid`, including multiple keys for rotation.
- Replaceable claims validation, authentication conversion, and clock.
- A Spring Shell command for generating tokens.

## Installation

The project builds and tests with Java 25, Kotlin 2.3.0, and Spring Boot 4.1.0.

Declare the library and Spring Boot starters in your application:

```kotlin
dependencies {
    implementation("io.github.kostack:jwt-security:<version>")
    implementation("org.springframework.boot:spring-boot-starter-webflux")
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation("org.springframework.boot:spring-boot-starter-security-oauth2-resource-server")
    implementation("org.springframework.boot:spring-boot-starter-oauth2-client")
}
```

The four Spring Boot starters are compile-only dependencies of the main library.
Applications supply them and manage their versions through Spring Boot dependency management.
Spring Shell remains a runtime dependency of the library.

## Quick start

### 1. Generate and encode an RSA key pair

The private key must be an unencrypted PKCS#8 PEM key (`BEGIN PRIVATE KEY`).
The public key must be an X.509 SubjectPublicKeyInfo PEM key (`BEGIN PUBLIC KEY`).

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out private.pem
openssl pkey -in private.pem -pubout -out public.pem

export JWT_PRIVATE_KEY_BASE64="$(base64 < private.pem | tr -d '\n')"
export JWT_PUBLIC_KEY_BASE64="$(base64 < public.pem | tr -d '\n')"
```

Each configuration value contains the Base64 encoding of the **entire PEM file**,
including its header and footer. File paths, raw PEM text, and Base64-encoded DER alone
are not accepted. Surrounding whitespace on the outer Base64 value is trimmed.

### 2. Configure `application.yml`

```yaml
kostack-security:
  issuer:
    kid: https://issuer.example.com
    audience: example-api
    private-key: ${JWT_PRIVATE_KEY_BASE64}
    algorithm-signature: RS512
    expiration-time: 3600
  trusted-issuers:
    local:
      issuer: https://issuer.example.com
      audience: example-api
      algorithm: RS512
      public-key: ${JWT_PUBLIC_KEY_BASE64}
  authorities-claim: roles
  authority-prefix: ""
  authorization-header:
    name: Authorization
    prefix: Bearer
  query-parameter:
    enabled: false
    name: token
```

To decode your own tokens, explicitly trust the signing issuer under `trusted-issuers`.
Its issuer, audience, and algorithm must match the signing configuration. For inline
verification, the token's `kid` must equal the trusted `issuer` value, so configure the
signing `issuer.kid` to match the trusted issuer value. It sets both `kid` and `iss`.
Each trusted issuer accepts one inline `public-key`; it has no separate `kid` setting.
The former `issuer.name` and `public-keys` settings are no longer supported.

### 3. Define your user and user provider

Implement `JwtUser.identity` and `claims()`:

```kotlin
import io.github.kostack.jwt_security.dto.JwtUser

data class AppUser(
    val username: String,
    val roles: List<String>
) : JwtUser {
    override val identity: String
        get() = username

    override fun claims(): Map<String, Any> =
        mapOf("username" to username, "roles" to roles)
}
```

Register a `UserProvider` bean to load the application user by the JWT subject.
This example uses an in-memory directory; replace it with your own user lookup:

```kotlin
import io.github.kostack.jwt_security.dto.JwtUser
import io.github.kostack.jwt_security.service.UserProvider
import org.springframework.stereotype.Service

@Service
class AppUserProvider : UserProvider {
    private val users = mapOf(
        "alice" to AppUser("alice", listOf("ROLE_USER"))
    )

    override suspend fun load(
        identity: String,
        claims: Map<String, Any>
    ): JwtUser? = users[identity]
}
```

During HTTP authentication, `load` receives the validated JWT's subject and claims.
Returning `null` rejects authentication. The default provider contains an
unimplemented placeholder, so applications using the default authentication flow
must supply their own provider.

The resulting authentication is a `UsernamePasswordAuthenticationToken` with the loaded
user as its principal and null credentials. Its authorities come from the JWT's configured
authorities claim, rather than from the loaded user's `claims()` result.
With the default empty authority prefix, use `ROLE_USER` in the JWT for `hasRole("USER")`.

### 4. Configure the security filter chain

The library supplies authentication components, but your application defines its own
`SecurityWebFilterChain`. Wire both the token extractor and JWT authentication converter
into Spring Security's OAuth2 resource server:

```kotlin
import io.github.kostack.jwt_security.converter.HeaderOrQueryTokenAuthenticationConverter
import io.github.kostack.jwt_security.converter.JwtAuthenticationConverter
import io.github.kostack.jwt_security.service.AuthEntryPointJwt
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository

@Configuration
@EnableWebFluxSecurity
class WebSecurityConfiguration {
    @Bean
    fun securityWebFilterChain(
        http: ServerHttpSecurity,
        tokenConverter: HeaderOrQueryTokenAuthenticationConverter,
        jwtConverter: JwtAuthenticationConverter,
        entryPoint: AuthEntryPointJwt
    ): SecurityWebFilterChain =
        http
            .csrf { it.disable() }
            .formLogin { it.disable() }
            .httpBasic { it.disable() }
            .logout { it.disable() }
            .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
            .exceptionHandling { it.authenticationEntryPoint(entryPoint) }
            .authorizeExchange {
                it.pathMatchers("/public/**").permitAll()
                    .anyExchange().authenticated()
            }
            .oauth2ResourceServer {
                it.bearerTokenConverter(tokenConverter)
                it.authenticationEntryPoint(entryPoint)
                it.jwt { jwt -> jwt.jwtAuthenticationConverter(jwtConverter) }
            }
            .build()
}
```

This example configures a stateless API using explicit bearer tokens.
The auto-configured `ReactiveJwtDecoder` handles signature and claim validation.

## Encoding and decoding

Inject the library's `io.github.kostack.jwt_security.encoder.JwtEncoder`:

```kotlin
import io.github.kostack.jwt_security.dto.JwtUser
import io.github.kostack.jwt_security.encoder.JwtEncoder
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.stereotype.Service
import java.time.Clock

@Service
class TokenService(private val encoder: JwtEncoder, private val clock: Clock) {
    suspend fun issue(user: JwtUser): String =
        encoder.encode(user, mapOf("tenant" to "acme"))

    suspend fun issueShortLived(user: JwtUser): String =
        encoder.encode(user, mapOf("tenant" to "acme"), expiresAt = clock.instant().plusSeconds(60))

    suspend fun inspect(token: String): Jwt = encoder.decode(token)
}
```

`encode` and `decode` are suspending functions. `encoder.decoder()` returns a
`ReactiveJwtDecoder` for Reactor integrations. Issue a token only after your
application has authenticated the user; `encode` does not perform credential checks.

The optional `expiresAt: Instant?` argument sets the absolute expiry for the token.
Omitting it or passing `null` uses the injected clock's current time plus
`issuer.expiration-time` seconds. An explicit timestamp is used directly for `exp`.
The encoder overrides any supplied `exp` claim. Past timestamps are preserved;
decoding an expired token fails validation.

Token issuance uses:

| Field | Source |
|---|---|
| Header `kid` | `issuer.kid` |
| Header `alg` | `issuer.algorithm-signature` |
| `sub` | `JwtUser.identity` |
| `iss` | `issuer.kid` |
| `aud` | Includes `issuer.audience` |
| `iat` | Current injected clock time |
| `nbf` | Current clock time minus one second |
| `exp` | Absolute `expiresAt`, or current injected clock time plus `issuer.expiration-time` seconds when omitted or null |

Additional claims override entries returned by `user.claims()`.
The encoder then sets the subject, issuer, and timestamps, overriding supplied values
for those fields. It adds the configured audience to any supplied audiences.

Decoding verifies the signature using the trusted issuer's configured algorithm.
Inline RSA keys require a known `kid`. The default setup also checks the trusted issuer, expiration and not-before times, audience membership,
a nonblank subject, and the presence of the configured authorities claim and expiration.
Timestamp checks use the injected clock with zero clock skew. An empty authorities list is
accepted; the required-claims validator checks the claim's presence.

## Token extraction

The default request format is:

```http
Authorization: Bearer <token>
```

To accept raw tokens through a custom header:

```yaml
kostack-security:
  authorization-header:
    name: x-auth
    prefix: ""
```

Enable a query parameter separately:

```yaml
kostack-security:
  query-parameter:
    enabled: true
    name: token
```

Then a request may supply `?token=<token>`. A valid header token takes precedence.
When the header is absent or uses an unrelated scheme, extraction can fall back to the
query parameter. A malformed matching header fails authentication instead of falling back.
Header prefixes are trimmed in configuration and matched without regard to case.

The `authorization-header.enabled` property currently has no effect: the converter
always checks the configured header. To replace extraction behavior, provide a
`HeaderOrQueryTokenAuthenticationConverter` subclass bean and override `convert`.

## Key IDs and rotation

Configure one inline public key per trusted issuer. The issuer value also serves as its key ID:

```yaml
kostack-security:
  issuer:
    kid: https://issuer.example.com
    audience: example-api
    private-key: ${JWT_CURRENT_PRIVATE_KEY_BASE64}
  trusted-issuers:
    local:
      issuer: https://issuer.example.com
      audience: example-api
      algorithm: RS512
      public-key: ${JWT_CURRENT_PUBLIC_KEY_BASE64}
```

Inline verification requires `kid` and `iss` to equal the configured trusted issuer.
Replacing the inline public key stops accepting tokens signed with the previous key.
For rotation with overlapping keys, use a remote JWKS endpoint that publishes both
keys during the transition. Remote JWKS verification uses the key IDs published by
that endpoint; those IDs may differ from the issuer.

Keys are scoped to their trusted issuer. Each issuer must configure exactly one
source: one inline `public-key` or a remote `jwk-set-uri`.

### Accepting multiple token issuers

Configure each trusted issuer with its own JWKS URL, allowed algorithm, and expected audience:

```yaml
kostack-security:
  trusted-issuers:
    users:
      issuer: https://users.example.com
      jwk-set-uri: https://users.example.com/jwks
      algorithm: RS512
      audience: my-api
    partners:
      issuer: https://partners.example.com
      jwk-set-uri: https://partners.example.com/jwks
      algorithm: RS256
      audience: partner-api
```

HTTP authentication and direct `JwtEncoder.decode()` calls use the same trusted-issuer
configuration. The token's `iss` selects a configured decoder, which verifies its
signature using the configured algorithm and validates issuer, timestamps, and claims.
Only configured issuers are accepted; without a trust map all tokens are rejected.
The local signing issuer is not implicitly trusted. Inline-key issuers and remote JWKS
issuers can coexist in the map. Remote keys are fetched lazily and cached by Spring
Security. Each issuer's algorithm defaults to `RS512`.

A nonempty map also creates a `ReactiveAuthenticationManagerResolver<ServerWebExchange>`
bean for applications using `oauth2ResourceServer { it.authenticationManagerResolver(resolver) }`.
The fixture's `WebSecurityConfiguration` wires it automatically. The normal `jwt`
configuration also supports multiple issuers through the default `ReactiveJwtDecoder`.
The existing `JwtClaimsValidator` and `JwtAuthenticationConverter` beans are reused;
default required-claim validation checks each issuer's audience and the shared
authorities claim. Duplicate issuers, missing issuer or audience, and ambiguous or
missing key sources fail at startup.

Token issuance continues using `issuer.private-key` and the other signing settings.
Applications can replace the decoder or resolver by supplying their own beans.

## Auto-configuration and customization

Spring Boot discovers `SecurityAutoConfiguration` through its auto-configuration imports.
Each bean backs off when a matching bean already exists:

| Bean type | Default |
|---|---|
| `Clock` | `Clock.systemUTC()` |
| `AuthEntryPointJwt` | JSON unauthorized responses |
| `JwtKeyResolver` | Keys from `SecurityProperties` |
| `JwksService` | `JwksServiceImpl`, exporting configured inline public keys |
| `JwtEncoder` | `JwtEncoderImpl` |
| `GenerateToken` | Shell command when Spring Shell and a `UserProvider` bean are available |
| `ReactiveJwtDecoder` | `JwtEncoder.decoder()` |
| `ReactiveAuthenticationManagerResolver<ServerWebExchange>` | Per-issuer managers when `trusted-issuers` is nonempty |
| `HeaderOrQueryTokenAuthenticationConverter` | Header and optional query extraction |
| `JwtClaimsValidator` | `RequiredJwtClaimsValidator` |
| `JwtAuthenticationTokenFactory` | `JwtUserAuthenticationTokenFactory` |
| `ReactiveJwtAuthenticationConverter` | Authorities claim and prefix from properties |
| `JwtAuthenticationConverter` | Delegates authority conversion, then invokes the token factory |

No default `UserProvider` is registered. Supply one for the default user-loading
token factory and the token-generation command. Applications that replace user
loading with a custom `JwtAuthenticationTokenFactory` can omit `UserProvider`;
the default token-generation command will then be unavailable.

To extend required-claim validation, preserve the default checks when providing your own
`JwtClaimsValidator`. For example:

```kotlin
import io.github.kostack.jwt_security.autoconfigure.SecurityProperties
import io.github.kostack.jwt_security.encoder.JwtClaimsValidator
import io.github.kostack.jwt_security.encoder.RequiredJwtClaimsValidator
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult

@Configuration
class ClaimsConfiguration {
    @Bean
    fun jwtClaimsValidator(properties: SecurityProperties): JwtClaimsValidator {
        val requiredClaims = RequiredJwtClaimsValidator(properties)
        return JwtClaimsValidator { jwt ->
            val requiredResult = requiredClaims.validate(jwt)
            when {
                requiredResult.hasErrors() -> requiredResult
                jwt.getClaimAsString("tenant") == "acme" ->
                    OAuth2TokenValidatorResult.success()
                else -> OAuth2TokenValidatorResult.failure(
                    OAuth2Error("invalid_token", "Invalid tenant", null)
                )
            }
        }
    }
}
```

Replacing this bean replaces the required-claims checks. Issuer and timestamp validation
remain part of the default encoder's decoder. A custom `JwtAuthenticationTokenFactory`
can replace user loading and the resulting authentication type.

## Spring Shell

`SecurityAutoConfiguration` registers `GenerateToken` as a bean containing the Spring
Shell `@Command` when Spring Shell is present and a `UserProvider` bean is configured.
No component scanning or explicit import is required. It uses the
configured `UserProvider` and `JwtEncoder` beans and backs off when an application
supplies its own `GenerateToken` bean.

In a running application with an interactive Spring Shell:

```text
shell:> security:generate-token --identity alice
shell:> security:generate-token -u alice
```

The command calls `UserProvider.load(identity, emptyMap())`, encodes the returned user,
decodes the token, and prints the generated token, headers, and claims. A missing user
raises `UsernameNotFoundException`.

On Java 25, JLine may need native access enabled in the JVM that runs the application:

```bash
java --enable-native-access=ALL-UNNAMED -jar your-application.jar
```

For an IDE launch, add `--enable-native-access=ALL-UNNAMED` to that application's
VM options. The repository configures this flag for its Gradle test JVM only.
This repository builds a library JAR; run the shell from a consuming application.

## Authentication errors

When wired into the security filter chain, `AuthEntryPointJwt` returns HTTP 401
with `Content-Type: application/json`:

```json
{
  "status": 401,
  "error": "Unauthorized",
  "message": "Authentication token was either missing or invalid.",
  "path": "/api/protected"
}
```

The response path excludes query parameters, and the body does not include exception
details. If JSON serialization or the initial response write throws synchronously,
the entry point attempts a plain-text `Unauthorized` response with
`Content-Type: text/plain; charset=UTF-8`. Asynchronous write failures propagate.

## Configuration reference

All properties use the `kostack-security` prefix.

| Property | Default | Description |
|---|---|---|
| `issuer.kid` | `local` | Signing key ID in the JWT header and issuer in the `iss` claim |
| `issuer.audience` | `""` | Audience added on issuance; trusted issuers configure decoding audiences |
| `issuer.private-key` | `""` | Base64-encoded PKCS#8 PEM private key |
| `issuer.algorithm-signature` | `RS512` | Signing algorithm: RS256, RS384, or RS512 |
| `issuer.expiration-time` | `3600` | Default token lifetime in seconds (`Long`) when `expiresAt` is omitted or null |
| `trusted-issuers` | `{}` | Named trusted issuers; a nonempty map enables the resolver bean |
| `trusted-issuers.<name>.issuer` | `""` | Exact expected `iss` claim and inline key ID; required |
| `trusted-issuers.<name>.jwk-set-uri` | `""` | Absolute HTTP(S) JWKS endpoint; alternative to inline keys |
| `trusted-issuers.<name>.public-key` | `""` | One Base64-encoded X.509 PEM public key; alternative to JWKS |
| `trusted-issuers.<name>.algorithm` | `RS512` | Allowed signature algorithm for this issuer |
| `trusted-issuers.<name>.audience` | `""` | Expected audience for this issuer; required |
| `authorities-claim` | `roles` | Claim used to extract granted authorities |
| `authority-prefix` | `""` | Prefix added to each authority |
| `authorization-header.enabled` | `true` | Currently unused by the default converter |
| `authorization-header.name` | `Authorization` | Header containing the token |
| `authorization-header.prefix` | `Bearer` | Header scheme; empty string accepts a raw token |
| `query-parameter.enabled` | `false` | Enables query-parameter token extraction |
| `query-parameter.name` | `""` | Query parameter name; set it when enabling extraction |

## Development and coverage

Use a Java 25 toolchain.

```bash
./gradlew test
./gradlew check
./gradlew jacocoTestReport
```

- `test` runs the JUnit tests.
- `check` runs tests, Spotless formatting checks, and JaCoCo coverage verification.
  It fails when overall instruction coverage is below **80%**.
- `jacocoTestReport` depends on `test` and generates HTML at
  `build/jacocoHtml/index.html` and XML at `build/jacocoReport.xml`.
  Report generation is separate from `check`.

Run `./gradlew spotlessApply` to format Kotlin sources and Gradle scripts.

The fixture application's `application.yml` shows a local inline-key issuer and an
example remote issuer. `TestApplication.main` supplies temporary local keys through
`TestJwtKeys.properties` as Spring default properties. YAML, environment variables,
and command-line arguments override matching defaults; issuer map entries with
different names are merged. Configure the remote entry for your server or remove it
when only local tokens are needed.

Integration tests load `src/test/resources/jwt-security-test.yml` using
`spring.config.name=jwt-security-test`, so edits to the fixture application's YAML
do not change their trusted issuers. `ApiControllerTest` supplies generated local
keys through `@DynamicPropertySource`; `MultiIssuerApiControllerTest` supplies two
remote issuers backed by an HTTP server on a random loopback port. Tests do not
require the example JWKS server on port 8080.

## License

MIT
