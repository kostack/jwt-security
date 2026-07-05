# JWT Security

A Kotlin/Spring Boot WebFlux library for reactive JWT authentication using RSA key pairs.

## Features

- RSA-signed JWT generation and validation (RS256/RS512)
- Reactive Spring Security integration (WebFlux)
- Pluggable token extraction (Authorization header, query parameter)
- Multi-issuer public key support
- Spring Shell CLI command for generating test tokens

## Installation

Add the dependency to your `build.gradle.kts`:

```kotlin
dependencies {
    implementation("io.github.kostack:jwt-security:<version>")
}
```

## Quick Start

The library auto-configures its JWT properties, key resolver, manager, token extractors,
authentication converter, authentication manager, unauthorized entry point, and Spring Shell command.
You still define your own `SecurityWebFilterChain` so each application can choose its public and protected routes.

### 1. Generate RSA Key Pair

```bash
# Private key
openssl genrsa -out private.pem 2048
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in private.pem -out private_pkcs8.pem

# Public key
openssl rsa -in private.pem -pubout -out public.pem
```

### 2. Configure `application.yml`

```yaml
jwt:
  issuer: my-service
  expiration: 3600         # seconds (default: 3600)
  private_key: keys/private_pkcs8.pem
  signature_algorithm: RS512  # RS512 or RS256 (default: RS512)
  public_keys:
    my-service: keys/public.pem
  authorizationHeaderOptions:
    enabled: true
    name: Authorization
    prefix: Bearer
  queryParameterOptions:
    enabled: false
    name: bearer
```

### 3. Implement `JwtUser`

```kotlin
@Entity
data class User(
    val username: String,
    val email: String,
    val roles: List<String>
) : JwtUser {

    override val identity: String
        get() = username

    override fun toMap(): Map<String, Any> = mapOf(
        "username" to username,
        "email" to email,
        "roles" to roles
    )
}
```

> **Note:** The `toMap()` result becomes JWT claims. A `"roles"` claim (list of strings) is required for Spring Security role-based access.

### 4. Implement `JwtUserService`

```kotlin
@Service
class UserService(private val userRepository: UserRepository) : JwtUserService {

    override suspend fun findByIdentity(identity: String): JwtUser? =
        userRepository.findByUsername(identity)

    override suspend fun upsertFromPayload(payload: Map<String, Any>): JwtUser {
        val username = payload["username"] as String
        val email = payload["email"] as String
        @Suppress("UNCHECKED_CAST")
        val roles = payload["roles"] as List<String>

        return userRepository.save(User(username, email, roles))
    }
}
```

### 5. Configure Spring Security

```kotlin
@Configuration
@EnableWebFluxSecurity
class WebSecurityConfiguration(
    private val authenticationManager: TokenAuthenticationManager,
    private val authenticationConverter: JwtServerAuthenticationConverter,
    private val authEntryPoint: AuthEntryPointJwt
) {

    @Bean
    fun securityWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
        val authFilter = AuthenticationWebFilter(authenticationManager).apply {
            setServerAuthenticationConverter(authenticationConverter)
        }

        return http
            .csrf { it.disable() }
            .httpBasic { it.disable() }
            .formLogin { it.disable() }
            .exceptionHandling { it.authenticationEntryPoint(authEntryPoint) }
            .authorizeExchange { exchanges ->
                exchanges
                    .pathMatchers("/auth/**").permitAll()
                    .anyExchange().authenticated()
            }
            .addFilterAt(authFilter, SecurityWebFiltersOrder.AUTHENTICATION)
            .build()
    }
}
```

## Token Generation

### Via `JwtManager`

```kotlin
@RestController
@RequestMapping("/auth")
class AuthController(
    private val jwtManager: JwtManager,
    private val userRepository: UserRepository
) {

    @PostMapping("/login")
    suspend fun login(@RequestBody request: LoginRequest): TokenResponse {
        val user = userRepository.findByUsername(request.username)
            ?: throw ResponseStatusException(HttpStatus.UNAUTHORIZED)

        // validate password...

        val token = jwtManager.generateToken(user)
        return TokenResponse(token)
    }
}
```

### Via Spring Shell CLI

Useful for local testing without a running HTTP server:

```bash
./gradlew bootRun

shell:> security:generate-token --identity alice
shell:> security:generate-token -u alice
```

Output:

```
Token: eyJhbGciOiJSUzUxMiJ9...

+----------+------------------------------+
| Claim    | Value                        |
+----------+------------------------------+
| sub      | alice                        |
| roles    | [admin, user]                |
| iss      | my-service                   |
| iat      | 2026-06-26T10:00:00Z         |
| exp      | 2026-06-26T11:00:00Z         |
+----------+------------------------------+
```

## Multi-Issuer Support

To accept tokens from multiple services, register their public keys:

```yaml
jwt:
  issuer: my-service            # issuer used when signing tokens
  private_key: keys/private_pkcs8.pem
  public_keys:
    my-service: keys/my-service-public.pem
    partner-service: keys/partner-public.pem
    legacy-service: keys/legacy-public.pem
```

The library reads the `kid` header from incoming JWTs and resolves the matching public key automatically.

## Token Extraction

Tokens can be extracted from multiple locations. Both can be active simultaneously:

```yaml
jwt:
  authorizationHeaderOptions:
    enabled: true
    name: Authorization   # header name
    prefix: Bearer        # stripped before parsing
  queryParameterOptions:
    enabled: true
    name: bearer          # ?bearer=<token>
```

### Custom Extractor

Implement `TokenExtractor` to support cookies, custom headers, etc.:

```kotlin
@Component
class CookieExtractor : TokenExtractor {
    override fun extract(request: ServerHttpRequest): String? =
        request.cookies["jwt"]?.firstOrNull()?.value
}
```

The `JwtServerAuthenticationConverter` tries all registered `TokenExtractor` beans in order and uses the first non-null result.

## Error Response

Failed authentication returns a structured JSON `401`:

```json
{
  "status": 401,
  "error": "Unauthorized",
  "message": "Full authentication is required to access this resource",
  "path": "/api/protected"
}
```

## Configuration Reference

| Property | Type | Default | Description |
|---|---|---|---|
| `jwt.issuer` | `String` | — | JWT `iss` claim and `kid` header value |
| `jwt.expiration` | `Int` | `3600` | Token lifetime in seconds |
| `jwt.private_key` | `String` | — | Path to PKCS8 PEM private key file |
| `jwt.signature_algorithm` | `String` | `RS512` | `RS512` or `RS256` |
| `jwt.public_keys` | `Map<String, String>` | — | Issuer → public key PEM path |
| `jwt.authorizationHeaderOptions.enabled` | `Boolean` | — | Enable header extraction |
| `jwt.authorizationHeaderOptions.name` | `String` | — | Header name |
| `jwt.authorizationHeaderOptions.prefix` | `String` | — | Token prefix (e.g. `Bearer`) |
| `jwt.queryParameterOptions.enabled` | `Boolean` | — | Enable query param extraction |
| `jwt.queryParameterOptions.name` | `String` | — | Query parameter name |

## License

MIT
