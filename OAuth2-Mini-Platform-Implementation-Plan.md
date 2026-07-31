# Implementation Plan — Mini OAuth 2.0 JWT Platform

## 1. Objective

Build exactly the two Spring Boot REST APIs requested in the specification:

1. An **Authorization Server** that accepts a subject in a `POST` request and returns a signed JWT access token.
2. A **Resource Server** that exposes a secured HelloWorld endpoint.
3. The Resource Server verifies the JWT signature and validates its claims.
4. A key-change scenario proves that the Resource Server can validate a token signed with a newly generated key without restarting.
5. A Postman collection demonstrates the complete flow.

This solution is intentionally small. It applies sound security and testing practices without adding unrelated OAuth flows or platform infrastructure.

## 2. Scope boundary

### Included

- JWT issuance from a subject supplied by the caller
- RSA signing with a key identifier (`kid`)
- Public JSON Web Key Set (JWKS)
- Bearer-token authentication
- Signature and claim validation
- Secured HelloWorld endpoint
- Simulated signing-key change
- Automated unit and integration tests
- Postman end-to-end demonstration
- Clear setup and architecture documentation

### Not included

The specification does not require:

- User login, consent pages, or browser redirects
- Client registration or client authentication
- Authorization Code, Client Credentials, Device Code, or Refresh Token flows
- Scopes, roles, or fine-grained authorization
- Persistent users, clients, tokens, or keys
- Token revocation or introspection
- A complete signing-key rotation lifecycle with an overlap period
- A database, message broker, cache, containers, or orchestration
- Monitoring, audit infrastructure, or deployment configuration

The token endpoint is therefore an exercise-specific JWT issuance endpoint, not a complete standards-compliant OAuth authorization provider. This distinction must be stated in the README.

The JWT is also a private token profile for this two-service system. It does not claim conformance with RFC 9068, because that OAuth access-token profile requires information such as `client_id`, while this exercise has no client-registration requirement.

## 3. Technology choices

| Area | Choice | Reason |
|---|---|---|
| Java | Java 21 | Matches the installed OpenJDK 21 LTS runtime |
| Build | Maven Wrapper, multi-module project | Reproducible build and one command for both applications |
| Framework | Spring Boot 4.1.x | Current Spring Boot generation compatible with Java 21 |
| Security | Spring Security 7.1.x, managed by Spring Boot | Standard JWT and Resource Server support |
| JWT implementation | Spring Security JOSE APIs backed by Nimbus JOSE + JWT | Avoids custom cryptographic and JWT parsing code |
| Signature algorithm | `RS256` with 2048-bit RSA keys | Widely supported asymmetric signature; Resource Server needs only the public key |
| Tests | JUnit Jupiter, AssertJ, Spring Boot Test, Spring Security Test | Focused unit and HTTP/security integration testing |
| Demonstration | Postman collection and environment | Explicitly requested and easy to reproduce |

Dependency versions should come from the Spring Boot parent/BOM. Do not manually override Spring Security or Nimbus versions.

### Module dependencies

Authorization Server:

- `spring-boot-starter-webmvc`
- `spring-boot-starter-security`
- `spring-boot-starter-validation`
- `spring-security-oauth2-jose`
- `spring-boot-starter-test` with test scope
- `spring-security-test` with test scope

Resource Server:

- `spring-boot-starter-webmvc`
- `spring-boot-starter-oauth2-resource-server`
- `spring-boot-starter-validation`
- `spring-boot-starter-test` with test scope
- `spring-security-test` with test scope

Use `spring-boot-starter-webmvc`, which is the non-deprecated Spring Boot 4 MVC starter. The key-change fixture can use the JDK's small built-in HTTP server and therefore needs no additional mock-server dependency.

## 4. Architecture

```text
Client / Postman
      |
      | POST /api/v1/tokens
      | Content-Type: application/x-www-form-urlencoded
      | body: subject=alice
      v
Authorization Server :9000
      |
      | returns signed JWT with kid=key-A
      v
Client / Postman
      |
      | GET /api/v1/hello
      | Authorization: Bearer <JWT>
      v
Resource Server :8080
      |
      | obtains matching public key when needed
      | GET http://localhost:9000/oauth2/jwks
      v
Authorization Server JWKS endpoint
```

The services have separate responsibilities:

- The Authorization Server owns the RSA key pair and signs tokens with the private key.
- Its JWKS endpoint publishes only the public key.
- The Resource Server never receives or stores the private key.
- The Resource Server selects a public key using the JWT header's `kid`, verifies the signature, and validates the required claims before invoking the controller.

## 5. Repository structure

```text
.
├── pom.xml
├── mvnw
├── mvnw.cmd
├── .mvn/
│   └── wrapper/
├── authorization-server/
│   ├── pom.xml
│   └── src/
│       ├── main/
│       │   ├── java/io/github/yousseflah/oauth/authorization/
│       │   │   ├── AuthorizationServerApplication.java
│       │   │   ├── config/
│       │   │   │   ├── AuthorizationProperties.java
│       │   │   │   ├── JwtConfiguration.java
│       │   │   │   └── SecurityConfiguration.java
│       │   │   ├── token/
│       │   │   │   ├── TokenController.java
│       │   │   │   ├── TokenService.java
│       │   │   │   └── TokenResponse.java
│       │   │   └── jwk/
│       │   │       ├── EphemeralRsaKeyProvider.java
│       │   │       └── JwkSetController.java
│       │   └── resources/application.yml
│       └── test/java/...
├── resource-server/
│   ├── pom.xml
│   └── src/
│       ├── main/
│       │   ├── java/io/github/yousseflah/oauth/resource/
│       │   │   ├── ResourceServerApplication.java
│       │   │   ├── config/
│       │   │   │   ├── ResourceSecurityProperties.java
│       │   │   │   └── SecurityConfiguration.java
│       │   │   └── hello/
│       │   │       ├── HelloController.java
│       │   │       └── HelloResponse.java
│       │   └── resources/application.yml
│       └── test/java/...
├── postman/
│   ├── OAuth2-Mini-Platform.postman_collection.json
│   └── Local.postman_environment.json
└── README.md
```

Use `io.github.yousseflah.oauth` as the stable package prefix in both modules.

## 6. API contracts

### 6.1 Issue a token

```http
POST /api/v1/tokens HTTP/1.1
Host: localhost:9000
Content-Type: application/x-www-form-urlencoded
Accept: application/json

subject=alice
```

Successful response:

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store
Pragma: no-cache
```

```json
{
  "access_token": "<signed-jwt>",
  "token_type": "Bearer",
  "expires_in": 300
}
```

Rules:

- `subject` is a required form parameter.
- Accept the subject only in the form body; reject query strings on the token route to prevent exposure through request-line logs and history.
- Trim leading and trailing whitespace.
- Reject blank values.
- Limit the normalized value to 100 characters.
- Accept a conservative character set such as letters, digits, `.`, `_`, `@`, and `-`.
- Implement the allowlist as one precompiled immutable `Pattern` and apply it after normalization.
- Invalid input returns `400 Bad Request` using Spring's `ProblemDetail`.
- Do not return a refresh token or unrequested OAuth fields.

The endpoint is public because the exercise explicitly asks the caller to obtain a token by submitting only a subject. The README must note that a real issuer would authenticate the user or client before issuing a token.

### 6.2 Obtain signing public keys

```http
GET /oauth2/jwks HTTP/1.1
Host: localhost:9000
```

Successful response:

```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "<unique-key-id>",
      "use": "sig",
      "alg": "RS256",
      "n": "<modulus>",
      "e": "AQAB"
    }
  ]
}
```

The response must never contain RSA private-key members such as `d`, `p`, `q`, `dp`, `dq`, or `qi`.

### 6.3 Access HelloWorld

```http
GET /api/v1/hello HTTP/1.1
Host: localhost:8080
Authorization: Bearer <access-token>
Accept: application/json
```

Successful response:

```http
HTTP/1.1 200 OK
Content-Type: application/json
```

```json
{
  "message": "Hello, alice!"
}
```

Authentication failures return `401 Unauthorized`, including:

- Missing bearer token
- Malformed JWT
- Invalid signature
- Expired token
- Wrong issuer
- Wrong audience
- Unsupported signing algorithm
- Missing or incorrect JWT `typ`
- A `kid` that cannot be resolved to a trusted public key

Bearer authentication responses must follow RFC 6750:

- A request without credentials returns `401` with `WWW-Authenticate: Bearer`.
- An invalid token returns `401` with a `WWW-Authenticate` Bearer challenge containing `error="invalid_token"`.
- Error descriptions must not expose token contents, key material, stack traces, or other internal details.

No scope or role check is added because the requirement asks only for an authenticated endpoint.

## 7. Authorization Server design

### 7.1 Configuration

Use type-safe `@ConfigurationProperties` for:

```yaml
server:
  port: 9000
  tomcat:
    max-http-form-post-size: 16KB

spring:
  mvc:
    problemdetails:
      enabled: true

application:
  security:
    issuer: http://localhost:9000
    audience: mini-resource-server
    token-type: oauth-mini+jwt
    access-token-ttl: 5m
```

Validate configuration at startup. Token timestamps must use an injected `Clock`, making time-dependent behavior deterministic in unit tests.

### 7.2 Ephemeral RSA key

`EphemeralRsaKeyProvider` must:

1. Generate one 2048-bit RSA key pair at application startup using JCA.
2. Generate a unique `kid`, for example a UUID. It is a public key selector and does not need to be secret or unpredictable.
3. Build an RSA JWK marked for signature use with algorithm `RS256`.
4. Retain the private JWK only inside the Authorization Server process.
5. Expose a public-only JWK representation for the JWKS endpoint.

Generate the key once, not once per request. Restarting the Authorization Server produces the new key used in the rotation simulation.

### 7.3 JWT encoder and token service

Configure Spring Security's `NimbusJwtEncoder` from the server's private JWK.

For each valid subject, `TokenService` creates:

| Location | Name | Value |
|---|---|---|
| Header | `alg` | `RS256` |
| Header | `typ` | `oauth-mini+jwt` |
| Header | `kid` | Current key identifier |
| Claim | `iss` | Configured issuer |
| Claim | `sub` | Normalized caller-supplied subject |
| Claim | `aud` | `mini-resource-server` |
| Claim | `iat` | Current instant |
| Claim | `exp` | Current instant plus five minutes |
| Claim | `jti` | New random UUID |

The service returns the compact token plus its lifetime in seconds. Controllers should contain HTTP mapping and input validation only; token construction remains in the service.

### 7.4 Authorization Server security chain

Use a stateless `SecurityFilterChain`:

- Permit `POST /api/v1/tokens`.
- Permit `GET /oauth2/jwks`.
- Deny every other request by default.
- Disable server sessions.
- Disable form login, HTTP Basic, and request caching.
- Disable CSRF for this stateless API because it does not authenticate with browser cookies.
- Return subject-validation and Spring MVC errors as sanitized `ProblemDetail` JSON without stack traces or internal details.
- Keep security and container errors sanitized; they use Spring Boot's default JSON error shape.

Keep Spring Security's default cache headers enabled so successful token responses include `Cache-Control: no-store` and `Pragma: no-cache`.

## 8. Resource Server design

### 8.1 Configuration

```yaml
server:
  port: 8080

application:
  security:
    issuer: http://localhost:9000
    jwk-set-uri: http://localhost:9000/oauth2/jwks
    audience: mini-resource-server
    token-type: oauth-mini+jwt
    jwks-connect-timeout: 2s
    jwks-read-timeout: 2s
```

Bind every value above to one validated `ResourceSecurityProperties` record using `@ConfigurationProperties`. The custom decoder bean reads only this record; do not also configure `spring.security.oauth2.resourceserver.jwt.*`, because exposing a custom `JwtDecoder` replaces Boot's decoder auto-configuration.

The explicit JWKS URI avoids requiring authorization-server discovery metadata. The issuer remains a separate value that must be validated on every JWT.

### 8.2 JWT decoder and validation

Build a custom `NimbusJwtDecoder` bean for the configured JWKS URI and explicitly allow only `RS256`.

Supply its JWKS client with short, explicit connection and read timeouts so a slow or unavailable key endpoint cannot tie up request-processing threads indefinitely.

The decoder wiring must follow this sequence:

1. Build the decoder with the configured JWKS URI, `RS256`, and the bounded `RestOperations`.
2. Call `validateType(false)` on the builder. This disables Nimbus's generic JOSE type verifier, which otherwise accepts only `JWT` or an absent type.
3. Construct a `JwtTimestampValidator`, retain its normal clock-skew tolerance, and require the `exp` claim.
4. Install one explicit validator chain containing:
   - The timestamp validator
   - `JwtIssuerValidator` with the configured issuer
   - A small audience validator requiring the configured audience
   - A subject validator requiring a nonblank `sub` claim
   - `JwtTypeValidator` requiring exactly the configured `oauth-mini+jwt`

The intended structure is:

```java
var decoder = NimbusJwtDecoder.withJwkSetUri(properties.jwkSetUri().toString())
        .jwsAlgorithm(SignatureAlgorithm.RS256)
        .validateType(false)
        .restOperations(jwksRestOperations)
        .build();

var timestampValidator = new JwtTimestampValidator();
timestampValidator.setAllowEmptyExpiryClaim(false);

decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
        timestampValidator,
        new JwtIssuerValidator(properties.issuer().toString()),
        new AudienceValidator(properties.audience()),
        new JwtClaimValidator<String>(
                JwtClaimNames.SUB,
                subject -> subject != null && !subject.isBlank()),
        new JwtTypeValidator(properties.tokenType())));
```

Do not call a `JwtValidators.createDefault...` factory and then append the private type validator: Spring Security 7's default chain includes the generic `JwtTypeValidator.jwt()`, which would conflict with `oauth-mini+jwt`.

The decoder must reject the request before controller execution if any validator or signature check fails.

The specific type prevents this Resource Server from accepting some other kind of JWT merely because it was signed by a trusted key.

Spring Security's remote JWKS support handles key selection by `kid` and refreshes the set when a token references an unknown key. Do not implement JWT parsing, signature verification, or an HTTP JWKS cache manually.

### 8.3 Resource Server security chain

Use a stateless `SecurityFilterChain`:

- Require authentication for `GET /api/v1/hello`.
- Deny all other requests by default.
- Enable OAuth 2.0 Resource Server JWT support.
- Disable sessions, form login, HTTP Basic, request caching, and CSRF.
- Use Spring Security's bearer authentication entry point so `401` responses include the RFC 6750 `WWW-Authenticate` challenge.

### 8.4 HelloWorld endpoint

`HelloController` obtains the authenticated subject from `Jwt` or `JwtAuthenticationToken` and returns an immutable `HelloResponse`.

It must not decode the bearer token itself. When the controller is called, Spring Security has already authenticated and validated the JWT.

## 9. Key-change simulation

The goal is only to prove acceptance of a token signed with a new key. A complete rollover system is deliberately outside scope.

### Procedure

1. Start both applications.
2. Request token A. Its header contains `kid=A`.
3. Call HelloWorld with token A and receive `200 OK`.
4. Keep the Resource Server running.
5. Restart only the Authorization Server. It generates key B with `kid=B`.
6. Request token B.
7. Call HelloWorld with token B.
8. The Resource Server sees the unknown `kid`, reloads the JWKS, verifies the token with public key B, and returns `200 OK`.

### Expected evidence

- Tokens A and B contain different `kid` values.
- The Resource Server process is not restarted.
- Token B is accepted.
- The JWKS never exposes a private key.

Old-key retention is not required. Depending on the JWKS cache state, token A may temporarily remain verifiable or may stop working after refresh; this is not presented as a complete rotation policy.

## 10. Testing strategy

Tests should prove behavior at the cheapest appropriate level. Do not create artificial service layers merely to increase the unit-test count.

### 10.1 Unit test definition

A unit test is a plain JUnit test with no Spring application context, network, filesystem, or real clock. Collaborators are constructed directly or replaced with focused fakes/mocks.

### 10.2 Authorization Server unit tests

`TokenServiceTest`:

- Uses a fixed `Clock`.
- Verifies `iss`, normalized `sub`, `aud`, `iat`, `exp`, and unique `jti`.
- Verifies the five-minute lifetime.
- Verifies protected header values `alg=RS256`, `typ=oauth-mini+jwt`, and the current `kid`.
- Verifies the returned `expires_in`.

Subject validation tests:

- Accept a valid subject.
- Trim surrounding whitespace.
- Reject missing, blank, oversized, or invalid-character values.

`EphemeralRsaKeyProviderTest`:

- Creates a 2048-bit RSA key.
- Assigns a nonblank unique `kid`.
- Produces a public JWK with no private parameters.

### 10.3 Authorization Server integration tests

Use `@SpringBootTest` with `@AutoConfigureMockMvc` and the real security filter chain:

- Valid form-encoded token request returns `200` and the documented response schema.
- Missing or invalid subject returns `400`.
- Token response includes no-store cache headers.
- Returned JWT signature verifies against the published JWKS.
- Returned JWT contains all required headers and claims.
- JWKS returns `200`, contains the current `kid`, and exposes no private material.
- Unmapped endpoints are denied.

### 10.4 Resource Server tests

The Resource Server has little standalone business logic, so its essential tests are security integration tests rather than artificial controller unit tests.

Use `@SpringBootTest` with `@AutoConfigureMockMvc` and a small static in-process HTTP JWKS test server bound to an ephemeral port. Register its runtime JWKS URL and the matching issuer through `@DynamicPropertySource` before the application context is created. Generate test RSA keys with the same JOSE library used by the application.

Keep the production clock-skew tolerance. For the expiration rejection test, set `exp` at least two minutes before the test clock so it is unambiguously outside the allowed skew.

Test:

- Missing token returns `401`.
- Valid signed token returns `200` and the subject-based greeting.
- Tampered signature returns `401`.
- Expired token returns `401`.
- Wrong issuer returns `401`.
- Wrong audience returns `401`.
- Missing or incorrect `typ` returns `401`.
- Token signed by an untrusted key returns `401`.
- An unsecured `alg=none` token returns `401`.
- An `HS256` token MACed using the RSA public-key bytes returns `401`, proving that the decoder cannot be tricked into treating an asymmetric public key as an HMAC secret.
- Missing credentials return `401` with `WWW-Authenticate: Bearer`.
- An invalid token returns `401` with a Bearer challenge containing `error="invalid_token"`.
- Unmapped endpoints are denied.

### 10.5 Automated key-change integration test

The mutable JWKS test server initially publishes public key A:

1. Send a token signed by A and assert `200`.
2. Change the served JWKS to public key B without recreating the Resource Server context.
3. Send a token signed by B with `kid=B`.
4. Assert `200`.

This test is the automated proof that a new signing key is discovered without restarting the Resource Server.

Implement and execute this automated test before relying on the manual demonstration. Keep Spring Security and Nimbus's default JWKS cache behavior unless the test demonstrates a real incompatibility; do not add cache or refresh infrastructure preemptively.

### 10.6 Build verification

The repository-level verification command is:

```bash
./mvnw clean verify
```

It must compile both applications and execute every unit and integration test.

## 11. Postman demonstration

Provide:

- A `Core flow` folder containing:
  - `Issue token`
  - `Call HelloWorld`
  - `Call HelloWorld without token`
  - `Read JWKS`
- A `Key change` folder containing:
  - `1 — Issue token A and remember kid`
  - A folder description instructing the user to restart only the Authorization Server
  - `2 — Issue token B and assert new kid`
  - `3 — Call HelloWorld with token B`
- A local environment containing:
  - `authorizationServerUrl=http://localhost:9000`
  - `resourceServerUrl=http://localhost:8080`
  - `subject=alice`
  - `accessToken`
  - `previousKid`
  - `currentKid`

Every token request sends `subject={{subject}}` as an `application/x-www-form-urlencoded` form field. The core `Issue token` test script saves `access_token` into the environment. The HelloWorld request uses:

```text
Authorization: Bearer {{accessToken}}
```

Postman assertions should check:

- Token request status is `200`.
- Response contains a nonempty access token.
- `token_type` equals `Bearer`.
- HelloWorld status is `200`.
- The greeting contains the requested subject.
- A call without a token returns `401`.
- The unauthenticated response contains a `WWW-Authenticate: Bearer` challenge.

The first key-change script base64url-decodes token A's JWT header, asserts that `kid` is present, and stores it as `previousKid`. After the documented Authorization Server restart, the second script:

1. Saves token B as `accessToken`.
2. Decodes its header and stores its `kid` as `currentKid`.
3. Asserts that `currentKid` is nonempty and differs from `previousKid`.

The last request calls HelloWorld with token B while the Resource Server remains running and asserts `200`. This makes the key-change checklist item reproducible without adding a key-rotation API.

## 12. Security baseline and OWASP considerations

Apply the controls relevant to each OWASP API Security Top 10 category. This is a scoped threat review, not a claim of formal OWASP certification.

| OWASP API risk | Treatment in this project |
|---|---|
| API1 Broken Object Level Authorization | No object identifier or object-level data endpoint exists; HelloWorld uses only the already validated principal |
| API2 Broken Authentication | Validate signature, type, issuer, audience, and time claims; use the standard bearer authentication entry point |
| API3 Broken Object Property Level Authorization | Use fixed immutable response models and no generic entity binding or mass assignment |
| API4 Unrestricted Resource Consumption | Limit form posts to 16 KB, bound the normalized subject to 100 characters, return bounded responses, and use short JWKS HTTP timeouts; rate limiting remains a documented requirement before exposing the intentionally public issuer outside the exercise |
| API5 Broken Function Level Authorization | Allow only the exact endpoint and HTTP-method combinations; deny everything else |
| API6 Unrestricted Access to Sensitive Business Flows | Treat token minting as sensitive; the lack of caller authentication is an explicit constraint and residual risk of the specification |
| API7 Server-Side Request Forgery | Read the JWKS URI only from trusted startup configuration, never from request input |
| API8 Security Misconfiguration | Stateless services, explicit security chains and algorithms, no default form login or generated user, and safe errors |
| API9 Improper Inventory Management | Document the complete two-endpoint API surface and deny undocumented routes |
| API10 Unsafe Consumption of APIs | Trust only the configured JWKS origin; apply HTTP timeouts and let the JOSE library parse and validate returned key data |

Additional rules:

- Never log the `Authorization` header or token response.
- Never commit private keys or secrets.
- Never put token contents into exception messages.
- Keep error messages generic while retaining useful server-side diagnostics.
- Treat HTTPS as mandatory outside local execution; local URLs remain HTTP solely for the reproducible demonstration.
- Use the five-minute expiration as the scoped mitigation for the absence of revocation.
- Do not add sensitive or unnecessary personal data to JWT claims because signed JWT contents are readable by their holder.

Known residual risks required by the exercise:

- Anyone who can reach the token endpoint can choose a subject and mint a token.
- The ephemeral signing key prevents old-key retention and intentional revocation.
- Local HTTP is acceptable only for the documented local demonstration.
- Tomcat rejects oversized forms before application validation, but repeated oversized requests can still create noisy error logs; edge limits and rate limiting are required outside this exercise.

These limitations must appear in the README and must not be presented as suitable defaults for a real public authorization service.

## 13. Implementation phases

Each phase below produces exactly one small commit. A phase includes its production code, directly related tests, and any documentation needed to understand that change.

For every phase:

1. Run its focused tests during development.
2. Run `./mvnw clean verify`.
3. Inspect `git diff` and remove unrelated changes.
4. Stage only the files belonging to that phase.
5. Commit only after the phase's completion condition is satisfied.
6. Push the commit to the configured GitHub branch without force-pushing.
7. Report the commit SHA, pushed branch, changed behavior, and verification result.
8. Stop and wait for explicit review approval before starting the next phase.

If a commit or push fails, report the failure and do not advance. If review feedback arrives, address it in a separate focused fix commit, rerun verification, push the fix, and wait for approval again. Do not rewrite shared history unless explicitly requested.

### Phase 1 — Java 21 multi-module skeleton

Commit:

```text
build: initialize Java 21 multi-module project
```

Tasks:

1. Obtain the Maven Wrapper through Spring Initializr because the local machine has Java 21 but no system Maven installation.
2. Create the parent POM and the `authorization-server` and `resource-server` modules.
3. Set Java release to 21 and use the `io.github.yousseflah.oauth` package prefix.
4. Add only the dependencies listed in this plan.
5. Add both Spring Boot entry points and minimal configuration.
6. Add one context-start smoke test per module.

Completion condition:

- Both modules compile and both application contexts start.
- `./mvnw clean verify` succeeds.

### Phase 2 — Authorization Server signing key

Commit:

```text
feat(auth): initialize RSA signing key
```

Tasks:

1. Add validated Authorization Server security properties.
2. Generate one RSA-2048 key pair at startup.
3. Assign a unique UUID `kid`.
4. Retain the private JWK internally and expose a public-only representation to application components.
5. Configure the `NimbusJwtEncoder`.
6. Add unit tests for key size, `kid`, public/private separation, and encoder availability.

Completion condition:

- One key is generated per application context.
- The public representation contains no private RSA parameters.

### Phase 3 — Public JWKS endpoint

Commit:

```text
feat(auth): publish public JWKS
```

Tasks:

1. Implement `GET /oauth2/jwks`.
2. Add the stateless default-deny Authorization Server security chain.
3. Permit only the JWKS endpoint at this stage.
4. Add full-context HTTP tests for the response structure, current `kid`, public parameters, and denied unknown routes.

Completion condition:

- The endpoint publishes the current public key.
- No private key member is serialized.

### Phase 4 — Signed JWT token service

Commit:

```text
feat(auth): create signed JWT access tokens
```

Tasks:

1. Implement normalized subject validation with one precompiled immutable `Pattern`.
2. Implement `TokenService` with an injected `Clock`.
3. Create the `RS256` header with `typ=oauth-mini+jwt` and the current `kid`.
4. Create `iss`, `sub`, `aud`, `iat`, `exp`, and unique `jti` claims.
5. Add plain unit tests for subject validation, headers, claims, lifetime, and deterministic timestamps.
6. Verify an encoded token against the public key in a focused integration test.

Completion condition:

- The service creates a verifiable five-minute JWT for a valid normalized subject.
- Invalid subjects cannot reach token encoding.

### Phase 5 — Token HTTP endpoint

Commit:

```text
feat(auth): expose form-encoded token endpoint
```

Tasks:

1. Implement `POST /api/v1/tokens` with a form-encoded `subject`.
2. Return `access_token`, `token_type`, and `expires_in`.
3. Add `Cache-Control: no-store` and `Pragma: no-cache`.
4. Permit the exact POST route in the existing security chain.
5. Return sanitized `ProblemDetail` responses for invalid input.
6. Add full-context HTTP tests for success, validation failures, cache headers, response schema, and denied method/path combinations.

Completion condition:

- A valid form request returns the documented signed JWT response.
- Invalid input returns `400` without leaking internal details.

### Phase 6 — Resource Server JWT decoder

Commit:

```text
feat(resource): configure JWT validation
```

Tasks:

1. Add the validated `ResourceSecurityProperties` record.
2. Add the ephemeral-port JWKS test server and register its URI through `@DynamicPropertySource`.
3. Configure bounded JWKS HTTP timeouts.
4. Build the custom `NimbusJwtDecoder` with `RS256` and `validateType(false)`.
5. Install the explicit timestamp, issuer, audience, and private-type validators.
6. Add integration tests that decode one valid token and reject individually wrong type, issuer, audience, and expiration.

Completion condition:

- The decoder accepts only a token matching the complete private token profile.
- No Spring Boot decoder configuration source competes with the custom properties.

### Phase 7 — Secured HelloWorld endpoint

Commit:

```text
feat(resource): secure HelloWorld endpoint
```

Tasks:

1. Add the stateless default-deny Resource Server security chain.
2. Enable bearer JWT authentication.
3. Implement `GET /api/v1/hello`.
4. Produce the greeting from the already authenticated JWT subject.
5. Preserve RFC 6750 bearer authentication challenges.
6. Add full-context HTTP tests for a valid token, a missing token, the greeting, denied unknown routes, and `WWW-Authenticate`.

Completion condition:

- A valid token returns the subject-based greeting.
- Missing credentials return `401` before controller execution.

### Phase 8 — JWT rejection hardening

Commit:

```text
test(resource): cover invalid JWT rejection
```

Tasks:

1. Add HTTP tests for a tampered signature and an untrusted key.
2. Add an expiration case at least two minutes outside the allowed clock skew.
3. Add wrong-type, wrong-issuer, and wrong-audience HTTP cases.
4. Add `alg=none` and HS256-with-RSA-public-key confusion cases.
5. Assert `401` and the RFC 6750 `invalid_token` challenge without sensitive error data.

Completion condition:

- Every documented invalid-token category is rejected through the real Spring Security filter chain.

### Phase 9 — Automated signing-key change

Commit:

```text
test(resource): verify signing key change
```

Tasks:

1. Extend the mutable JWKS fixture to publish key A and then key B.
2. Validate an A-signed token.
3. Change the served JWKS to B without recreating the Resource Server context.
4. Validate a B-signed token with a new `kid`.
5. Keep default caching unless this test demonstrates that explicit configuration is required.

Completion condition:

- A B-signed token succeeds without a Resource Server restart.

### Phase 10 — Postman core flow

Commit:

```text
test(postman): add core API workflow
```

Tasks:

1. Add the local Postman environment.
2. Add token issuance, HelloWorld, missing-token, and JWKS requests.
3. Send the subject as a form field.
4. Capture the access token automatically.
5. Add the core response and bearer-challenge assertions.

Completion condition:

- The core collection flow passes against both locally running applications.

### Phase 11 — Postman key-change flow

Commit:

```text
test(postman): add signing-key change workflow
```

Tasks:

1. Add the key-change folder and its manual restart checkpoint.
2. Decode and store token A's `kid`.
3. After restarting only the Authorization Server, decode token B's `kid`.
4. Assert that the key identifiers differ.
5. Call HelloWorld with token B while the Resource Server remains running.

Completion condition:

- Postman proves both the key change and acceptance of token B.

### Phase 12 — Reproducibility documentation

Commit:

```text
docs: add build and verification guide
```

Tasks:

1. Document architecture and responsibility boundaries.
2. Document prerequisites, build, test, and run commands.
3. Document API and Postman examples.
4. Document the key-change sequence.
5. Document security decisions, RFC boundaries, residual risks, and the JWKS-unavailability tradeoff.
6. Reproduce the build and manual demonstration from a clean application start.

Completion condition:

- A reader can reproduce every required behavior using only the README and committed files.
- The final `./mvnw clean verify` succeeds.

## 14. Final acceptance checklist

- [ ] Project uses Java 21.
- [ ] Repository contains exactly two runnable Spring Boot APIs.
- [ ] `POST /api/v1/tokens` with a form-encoded `subject` returns a signed JWT.
- [ ] JWT header contains `alg=RS256`, `typ=oauth-mini+jwt`, and `kid`.
- [ ] JWT contains `iss`, `sub`, `aud`, `iat`, `exp`, and `jti`.
- [ ] JWKS exposes the matching public key and no private data.
- [ ] `GET /api/v1/hello` requires a bearer token.
- [ ] Resource Server verifies signature, type, issuer, audience, and timestamps.
- [ ] Invalid tokens, including `alg=none` and HS256-confusion tokens, return `401`.
- [ ] Authentication failures carry the appropriate RFC 6750 `WWW-Authenticate` challenge.
- [ ] A new-key token succeeds without a Resource Server restart.
- [ ] Unit and integration tests pass with `./mvnw clean verify`.
- [ ] Postman demonstrates token issuance, secured access, failure without a token, and key change.
- [ ] README distinguishes this focused issuer from a complete OAuth authorization provider.
- [ ] No unrequested flow, persistence, infrastructure, or authorization feature has been added.

## 15. Standards, conformance boundary, and guidance

The references have different roles. Listing one here does not mean the project implements every feature in that document.

### Implemented protocol behavior

| Reference | Use in this project |
|---|---|
| [RFC 6750 — Bearer Token Usage](https://www.rfc-editor.org/rfc/rfc6750.html) | Send the token in the `Authorization: Bearer` header, require TLS outside local execution, and return standards-shaped bearer challenges |
| [RFC 7515 — JSON Web Signature](https://www.rfc-editor.org/rfc/rfc7515.html) | Produce and verify compact signed JWTs using established JOSE libraries |
| [RFC 7517 — JSON Web Key](https://www.rfc-editor.org/rfc/rfc7517.html) | Represent the RSA public key as a JWK and select it by distinct `kid` during key change |
| [RFC 7518 — JSON Web Algorithms](https://www.rfc-editor.org/rfc/rfc7518.html) | Use the registered `RS256` algorithm |
| [RFC 7519 — JSON Web Token](https://www.rfc-editor.org/rfc/rfc7519.html) | Encode and validate the `iss`, `sub`, `aud`, `iat`, `exp`, and `jti` registered claims |
| [RFC 8725 — JWT Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725.html) | Restrict algorithms, use strong keys, bind keys to a configured issuer, validate audience, and require the private token type `oauth-mini+jwt` |

### Architectural context only

[RFC 6749 — The OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749.html) defines the Authorization Server, Resource Server, client, grants, and token endpoint concepts. The project borrows those roles and its response uses `access_token`, `token_type`, `expires_in`, `Cache-Control: no-store`, and `Pragma: no-cache`.

The project does **not** claim RFC 6749 token-endpoint conformance: the PDF requires a `POST` containing only a subject, so there is no authorization grant, `grant_type`, client authentication, or resource-owner authorization.

The project also does **not** claim [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068.html) conformance. It uses a private `oauth-mini+jwt` type instead of `at+jwt` because the exercise has no `client_id`, which RFC 9068 requires.

### Implementation and security guidance

- [Spring Security — OAuth 2.0 Resource Server JWT](https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/jwt.html): decoder, validation, bearer authentication, JWKS retrieval, caching, and automatic key updates
- [OWASP API Security Top 10](https://owasp.org/API-Security/editions/2023/en/0x11-t10/): API threat review and relevant mitigations, with residual risks documented
- [OWASP JSON Web Token Cheat Sheet for Java](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html): Java JWT implementation guidance, short lifetime, algorithm restriction, safe handling, and key protection
