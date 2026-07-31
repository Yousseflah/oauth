# Repository Instructions

These instructions apply to the entire repository.

## Project scope

- Keep the implementation limited to the two services described in `OAuth2-Mini-Platform-Implementation-Plan.md`:
  - Authorization Server issuing a signed JWT from a supplied subject
  - Resource Server exposing a secured HelloWorld endpoint
- Support the documented JWKS-based signing-key change scenario.
- Do not add OAuth grants, client registration, scopes, refresh tokens, persistence, containers, or unrelated infrastructure unless the requirements change.
- Preserve the documented distinction between this focused JWT issuer and a complete RFC 6749 Authorization Server.

## Java

- Use Java 21.
- Prefer Java 21 language and library features when they make the code simpler, safer, or clearer.
- Prefer records for immutable request, response, configuration, and simple value objects when appropriate.
- Use switch expressions, pattern matching, text blocks, and other modern Java features where they improve readability.
- Do not use preview features.
- Use `var` for local variables whenever Java permits it and the initializer makes the inferred type understandable.
- Do not use `var` when it hides security-relevant behavior or makes the code harder to understand.
- Use explicit types where Java requires them, including fields, method parameters, and return types.
- Do not use Lombok. Write explicit constructors and methods when records are not suitable.
- Favor immutability, constructor injection, small cohesive classes, and package-private visibility where possible.
- Avoid static mutable state.

## Spring

- Use constructor injection; do not use field injection.
- Use validated `@ConfigurationProperties` for application settings.
- Keep controllers focused on HTTP concerns and delegate JWT construction or validation logic to dedicated components.
- Use Spring Security and Nimbus JOSE APIs for JWT encoding, decoding, signature verification, validation, JWKS retrieval, and key selection.
- Do not manually parse JWT strings or implement cryptographic algorithms.
- Configure security with explicit, stateless, default-deny `SecurityFilterChain` beans.
- Do not add scopes, roles, or method authorization unless a requirement needs them.

## Security

- Restrict JWT signatures to `RS256`.
- Validate the JWT signature, `typ`, issuer, audience, and timestamps before controller execution.
- Require the private token type `oauth-mini+jwt`.
- Publish only public JWK values. Never expose or serialize private RSA parameters.
- Never commit credentials, private keys, access tokens, or other secrets.
- Validate and normalize all external input.
- Keep authentication and validation errors useful but free of sensitive implementation details.
- Send bearer tokens only through the `Authorization` header.
- Preserve RFC 6750 `WWW-Authenticate` bearer challenges.

## Logging

- Add meaningful logs at service startup, key initialization, token issuance outcome, JWKS publication or refresh, and authentication failure boundaries when those logs help diagnose behavior.
- Use SLF4J parameterized logging, for example `log.info("Initialized signing key with kid={}", keyId)`.
- Choose log levels deliberately:
  - `INFO` for important lifecycle and successful state changes
  - `DEBUG` for diagnostic details useful during development
  - `WARN` for rejected input, authentication failures, and recoverable security-related problems
  - `ERROR` for unexpected failures requiring attention
- Include safe correlation information such as a generated request or event identifier when useful.
- Never log:
  - JWTs or token response bodies
  - `Authorization` headers
  - Private keys or private JWK parameters
  - Credentials or secrets
  - Raw cryptographic material
  - Sensitive personal data
- Do not log the supplied subject unless it is strictly necessary; prefer a safe event identifier.
- Do not log the same exception at multiple layers.
- Pass exceptions to the logger when a stack trace is useful, but return sanitized errors to clients.

## Code quality

- Prefer clear names over abbreviations.
- Keep methods short and focused on one responsibility.
- Remove dead code and unused dependencies.
- Avoid speculative abstractions and features that are not required.
- Add comments for security decisions and non-obvious tradeoffs, not for code that is already self-explanatory.
- Use RFC terminology accurately: JWT, JWS, JWK, JWKS, bearer token, issuer, audience, subject, and Resource Server are not interchangeable terms.

## Tests

- Use plain JUnit tests without a Spring context for true unit tests.
- Use `@SpringBootTest` with the real security filter chain for HTTP and security integration tests.
- Do not add slice tests.
- Use a fixed `Clock` in time-sensitive unit tests.
- Cover successful behavior and rejection of malformed, tampered, expired, wrong-type, wrong-issuer, wrong-audience, unsupported-algorithm, and untrusted-key tokens.
- Verify that JWKS responses never contain private key material.
- Verify RFC 6750 `WWW-Authenticate` responses.
- Keep tests deterministic and independent of execution order.
- Run the complete verification before considering a change finished:

```bash
./mvnw clean verify
```

## Change discipline

- Keep changes focused on the stated requirement.
- Do not silently broaden the system's OAuth capabilities.
- Update the README, Postman collection, tests, and implementation plan when an API contract or security behavior changes.
- Do not modify ignored study notes or the source PDF unless explicitly requested.
- Follow the phases in `OAuth2-Mini-Platform-Implementation-Plan.md` and create exactly one small commit per phase.
- Keep production code and its directly related tests in the same commit.
- Run `./mvnw clean verify` before every implementation commit.
- Inspect the staged diff before committing and exclude unrelated files or cleanup.
- Do not mix a feature, unrelated refactoring, and documentation cleanup in one commit.
- Use the commit message documented for the current phase.
- Push each completed phase commit to the configured GitHub branch without force-pushing.
- After pushing, report the commit SHA, branch, summary, and verification result to the user.
- Do not start work from the next phase until the user has reviewed the pushed commit and explicitly approved continuing.
- If the user requests changes, make a new focused fix commit, rerun verification, push it, and wait for approval again.
- If committing, verification, or pushing fails, report the failure and do not advance.
- Do not rewrite shared history unless explicitly requested.
