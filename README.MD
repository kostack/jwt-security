# JWT Security

A Kotlin library for RSA-signed JWTs and reactive Spring Security authentication in WebFlux applications.

## Features

- RSA token signing with RS256, RS384, or RS512.
- Coroutine APIs for encoding and decoding, plus a reactive JWT decoder.
- Header and optional query-parameter token extraction.
- Application-defined user loading and authentication principals.
- Issuer-scoped verification with inline RSA keys or remote JWKS for key rotation.
- Public JWKS export for configured inline RSA keys.
- Typed helpers for reading required and optional claims.
- Replaceable claims validation, authentication conversion, and clock.
- A Spring Shell command for generating tokens.

## Installation

The project builds and tests with Java 25, Kotlin 2.4.21, and Spring Boot 4.1.2.

Declare the library and the dependencies it expects the application to provide:

```kotlin
dependencies {
    implementation("io.github.kostack:jwt-security:<version>")
    implementation("org.springframework.boot:spring-boot-starter-webflux")
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation("org.springframework.boot:spring-boot-starter-security-oauth2-resource-server")
    implementation("org.springframework.boot:spring-boot-starter-oauth2-client")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-reactor")
    implementation("org.jetbrains.kotlin:kotlin-reflect")

    // Optional: only needed for the security:generate-token shell command.
    implementation("org.springframework.shell:spring-shell-starter-jni")
}
```

The Spring Boot starters, Kotlin coroutines, `kotlin-reflect`, and Spring Shell are
compile-only dependencies of the library and are not published with it. Applications
supply them and manage their versions through the Spring Boot BOM (and the Spring Shell
BOM when using the shell command). Without Spring Shell on the classpath, the token
command is simply not registered.

The library itself publishes only `jjwt-api` (API), plus `jjwt-impl`, `jjwt-jackson`,
`kotlinx-serialization-json`, and `ascii-table` at runtime, each with an explicit version.

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
      clock-skew: 60s
  authorities-claim: roles
  authority-prefix: ""
  authorization-header:
    enabled: true
    name: Authorization
    prefix: Bearer
  query-parameter:
    enabled: false
    name: token
```

To decode your own tokens, explicitly trust the signing issuer under `trusted-issuers`.
Its issuer, audience, and algorithm must match the signing configuration. The signing
`issuer.kid` sets both `kid` and `iss`, so it must equal the trusted `issuer` value.
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
Returning `null` rejects authentication. No default `UserProvider` is registered,
so applications using the default authentication flow must supply their own provider.

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
Inline RSA keys are selected by the token's `iss`; the `kid` header is not required. The default setup also checks the trusted issuer, expiration and not-before times, audience membership,
a nonblank subject, and the presence of the configured authorities claim and expiration.
Timestamp checks use the injected clock with the trusted issuer's `clock-skew`
(default `60s`; set `0s` for exact expiry). An empty authorities list is
accepted; the required-claims validator checks the claim's presence.

### Reading typed claims

Use the extensions on `Map<String, Any>` when reading claims in a user provider
or from a decoded JWT:

```kotlin
import io.github.kostack.jwt_security.extensions.getClaim
import io.github.kostack.jwt_security.extensions.getClaimOrNull

val jwt = encoder.decode(token)
val tenant = jwt.claims.getClaim<String>("tenant")
val displayName = jwt.claims.getClaimOrNull<String>("display_name")
```

`getClaim<T>` throws `IllegalArgumentException` when the claim is absent or its
value has the wrong type. `getClaimOrNull<T>` returns `null` for an absent claim
and throws for a type mismatch. Neither helper converts values; generic collection
element types are not checked at runtime.

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

Set `authorization-header.enabled: false` to ignore the header entirely, for example to
accept query-parameter tokens only. To replace extraction behavior, provide a
`HeaderOrQueryTokenAuthenticationConverter` subclass bean and override `convert`.

## Key IDs and rotation

Configure one inline public key per trusted issuer. Keys are selected by issuer; the
issuer value is also used as the `kid` for tokens this library signs and in the JWKS response:

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

Inline verification selects the key by `iss` and ignores the token's `kid`.
Replacing the inline public key stops accepting tokens signed with the previous key.
For rotation with overlapping keys, use a remote JWKS endpoint that publishes both
keys during the transition. Remote JWKS verification uses the key IDs published by
that endpoint; those IDs may differ from the issuer.

Keys are scoped to their trusted issuer. Each issuer must configure exactly one
source: one inline `public-key` or a remote `jwk-set-uri`.

### Trusting a remote issuer (JWKS)

To accept tokens signed by another service or identity provider, configure a trusted
issuer with a `jwk-set-uri` instead of a `public-key`. The library downloads that
issuer's public keys from the endpoint; no key material is configured locally.

```yaml
kostack-security:
  trusted-issuers:
    users:
      issuer: https://users.example.com          # must equal the token's `iss` exactly
      jwk-set-uri: https://users.example.com/.well-known/jwks.json
      algorithm: RS256                           # the only algorithm accepted from this issuer
      audience: my-api                           # the token's `aud` must contain this value
      clock-skew: 60s                            # optional, default 60s
```

Requirements, checked at startup:

- `issuer` and `audience` are required.
- `jwk-set-uri` must be an absolute `http` or `https` URL with a host. Use `https`
  outside local development.
- An issuer configures either `jwk-set-uri` or `public-key`, never both.
- `algorithm` may be any RSA, ECDSA, or RSA-PSS algorithm that the endpoint's keys
  support (the inline `public-key` option is limited to RS256, RS384, and RS512).

How verification works:

1. The token's `iss` selects the issuer's decoder; unknown issuers are rejected.
2. The token's `kid` header selects the key from the downloaded JWK set, so the remote
   issuer must sign with a `kid` that its JWKS publishes. Tokens signed with any
   algorithm other than the configured `algorithm` are rejected.
3. The JWK set is fetched on the first token from that issuer, not at startup, and is
   cached by Spring Security. When a token's `kid` is not in the cached set, the set is
   fetched again, so key rotation on the remote side needs no restart here.
4. The token is then validated like any other: issuer, `exp`/`nbf` within `clock-skew`,
   audience, a nonblank `sub`, and the presence of the `authorities-claim`.

If the endpoint is unreachable or returns no matching key, authentication fails with
401 for that request; startup is not affected.

> **Note:** The default `JwtClaimsValidator` requires the `authorities-claim`
> (`roles` by default) on tokens from **every** issuer. Tokens from identity providers
> that do not emit that claim are rejected. Either have the provider include it, or
> supply your own `JwtClaimsValidator` bean (see
> [Auto-configuration and customization](#auto-configuration-and-customization)).

#### Example: trusting another service that uses this library

Service A signs tokens and publishes its keys through the
[JWKS endpoint](#publishing-a-jwks-endpoint):

```yaml
# Service A
kostack-security:
  issuer:
    kid: https://service-a.example.com
    audience: service-b
    private-key: ${JWT_PRIVATE_KEY_BASE64}
  trusted-issuers:
    self:
      issuer: https://service-a.example.com
      audience: service-b
      public-key: ${JWT_PUBLIC_KEY_BASE64}   # exported at /.well-known/jwks.json
```

Service B accepts those tokens without holding any of A's keys:

```yaml
# Service B
kostack-security:
  trusted-issuers:
    service-a:
      issuer: https://service-a.example.com
      audience: service-b
      jwk-set-uri: https://service-a.example.com/.well-known/jwks.json
```

This works because tokens signed by this library carry `kid` = `issuer.kid`, and the
exported JWKS lists each inline key under `kid` = its trusted `issuer`. Keep the
`algorithm` (default `RS512`) the same on both sides.

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

### Publishing a JWKS endpoint

Inject `JwksService` to expose configured inline public keys to other services:

```kotlin
import io.github.kostack.jwt_security.jwks.JwksService
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class JwksController(private val jwksService: JwksService) {
    @GetMapping("/.well-known/jwks.json")
    fun publicKeys(): Map<String, Any> = jwksService.publicKeys()
}
```

Allow unauthenticated access to this endpoint in your application's security chain,
before `.anyExchange().authenticated()`:

```kotlin
it.pathMatchers("/.well-known/jwks.json").permitAll()
```

The library registers the service; your application supplies the controller and
access rule. The fixture application includes both.

The response contains a `keys` array with one RSA JWK per trusted issuer that has
an inline `public-key`. Each key includes `kid` equal to that issuer's `issuer`
value, `use: sig`, its configured `alg`, and the public RSA modulus and exponent.
Private key material is excluded. Remote JWKS entries are omitted, and no inline
keys produces an empty `keys` array. The signing private key alone does not add
a public key to the response; configure its corresponding inline trusted issuer
as shown in the quick start.

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
| `JwtAuthenticationTokenFactory` | `JwtUserAuthenticationTokenFactory` when a `UserProvider` bean is available |
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
Shell `@Command` when the application includes Spring Shell and a `UserProvider` bean is configured.
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
| `trusted-issuers.<name>.issuer` | `""` | Exact expected `iss` claim; selects the inline key; required |
| `trusted-issuers.<name>.jwk-set-uri` | `""` | Absolute HTTP(S) JWKS endpoint; alternative to inline keys |
| `trusted-issuers.<name>.public-key` | `""` | One Base64-encoded X.509 PEM public key; alternative to JWKS |
| `trusted-issuers.<name>.algorithm` | `RS512` | Allowed signature algorithm for this issuer |
| `trusted-issuers.<name>.audience` | `""` | Expected audience for this issuer; required |
| `trusted-issuers.<name>.clock-skew` | `60s` | Tolerance for `exp` and `nbf` checks; `0s` for exact expiry |
| `authorities-claim` | `roles` | Claim used to extract granted authorities |
| `authority-prefix` | `""` | Prefix added to each authority |
| `authorization-header.enabled` | `true` | Enables header token extraction; `false` ignores the header |
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
- `jacocoTestReport` runs automatically after `test` and generates HTML at
  `build/jacocoHtml/index.html` and XML at `build/jacocoReport.xml`.

Run `./gradlew spotlessApply` to format Kotlin sources and Gradle scripts.
`test` and `assemble` install `scripts/pre-commit` as the Git pre-commit hook
(if none exists), which runs the Spotless check before each commit.

Plugin versions for Kotlin are set once via `kotlinVersion` in `gradle.properties`.
Spring Boot and Spring Shell versions are managed by BOMs that apply only to compile-only,
test, and fixture dependencies, so they never appear in the published POM. The test
fixtures are not published.

The fixture application's `application.yml` shows a local inline-key issuer and an
example remote issuer. `TestApplication.main` supplies temporary local keys through
`TestJwtKeys.properties` as Spring default properties. YAML, environment variables,
and command-line arguments override matching defaults; issuer map entries with
different names are merged. Configure the remote entry for your server or remove it
when only local tokens are needed.

Integration tests load `src/test/resources/jwt-security-test.yml` using
`spring.config.name=jwt-security-test`, so edits to the fixture application's YAML
do not change their trusted issuers. `ApiControllerTest` supplies generated local
keys through `@DynamicPropertySource`. Tests do not require the example JWKS
server on port 8080. `JwksServiceImplTest` covers public-key export and signature
verification, and `JwksAutoConfigurationTest` checks default registration and
replacement with an application-provided service.

## License

MIT
