# OAuth 2.0 Mini Platform

This repository contains the two Java 21/Spring Boot REST APIs required by the technical specification:

- an **Authorization Server** that accepts a subject and issues a signed JWT;
- a **Resource Server** that validates that JWT and exposes a secured HelloWorld endpoint.

The project also demonstrates that the Resource Server can discover a newly generated signing key through JWKS without being restarted.

> [!IMPORTANT]
> The service named Authorization Server is an exercise-specific JWT issuer, not a complete OAuth 2.0 authorization provider. It has no grant, `grant_type`, client registration, client authentication, user login, consent, scopes, refresh tokens, or revocation endpoint. The supplied subject is not proof of identity.

## Architecture

```text
Client / Postman
    |
    | POST form body: subject=alice
    v
Authorization Server :9000
    |-- signs a five-minute JWT with its in-memory RSA private key
    |-- publishes only the RSA public key at /oauth2/jwks
    |
    | Authorization: Bearer <JWT>
    v
Resource Server :8080
    |-- selects a public key from JWKS by kid
    |-- verifies the signature and required token profile
    `-- invokes HelloWorld only after successful authentication
```

Responsibility boundaries:

| Component | Owns | Does not own |
|---|---|---|
| Authorization Server | Subject validation, ephemeral RSA key pair, JWT construction and signing, public JWKS | Grants, clients, user authentication, consent, token persistence |
| Resource Server | Bearer authentication, remote public-key retrieval, signature and claim validation, secured response | Private signing keys, token issuance, manual JWT decoding in the controller |
| Client/Postman | Token request, bearer-token transport, end-to-end assertions | Key material or server-side validation |

The Resource Server never receives the private key. Spring Security and Nimbus JOSE + JWT perform JOSE parsing, key selection, signing, signature verification, and JWT validation.

## Prerequisites

- JDK 21 available on `PATH`
- Bash-compatible shell for the commands below; on Windows, use `mvnw.cmd` for Maven commands
- Postman for the committed end-to-end collection
- Optional: `curl` and `jq` for the command-line examples

A separate Maven installation is not required; the Maven Wrapper is committed.

Confirm the Java runtime:

```bash
java -version
```

## Build and test

From the repository root:

```bash
./mvnw clean verify
```

This builds both modules and runs all unit and integration tests, including the real security filter chains and an automated JWKS key-change test.

## Run locally

First build the executable jars:

```bash
./mvnw clean verify
```

Start the Authorization Server in terminal 1:

```bash
java -jar authorization-server/target/authorization-server-0.0.1-SNAPSHOT.jar
```

Wait for the application-started log, then start the Resource Server in terminal 2:

```bash
java -jar resource-server/target/resource-server-0.0.1-SNAPSHOT.jar
```

Default local addresses:

| Application | Address |
|---|---|
| Authorization Server | `http://localhost:9000` |
| Resource Server | `http://localhost:8080` |

The Resource Server does not fetch JWKS during startup. Starting it successfully therefore does not prove that the Authorization Server or JWKS endpoint is reachable; the first request needing a public key performs the fetch.

## API

The intentionally small API surface is:

| Application | Method and path | Access | Purpose |
|---|---|---|---|
| Authorization Server | `POST /api/v1/tokens` | Public by specification | Issue a JWT for a form-body subject |
| Authorization Server | `GET /oauth2/jwks` | Public | Publish the current public signing key |
| Resource Server | `GET /api/v1/hello` | Bearer token required | Return a subject-based greeting |

All other method/path combinations are denied by default. The Resource Server also shadows Spring Security's automatically registered protected-resource metadata route so it cannot expand the documented API or advertise unsupported capabilities.

### Issue a token

The subject must be sent only in an `application/x-www-form-urlencoded` request body:

```bash
curl --silent --show-error --fail-with-body \
  --request POST http://localhost:9000/api/v1/tokens \
  --header 'Accept: application/json' \
  --header 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'subject=alice'
```

Response:

```json
{
  "access_token": "<signed-jwt>",
  "token_type": "Bearer",
  "expires_in": 300
}
```

Successful token responses include `Cache-Control: no-store` and `Pragma: no-cache`. A query string is rejected even if it contains a valid subject, preventing the subject from being accepted through a URL, proxy log, or shell history. The normalized subject must contain 1–100 letters, digits, `.`, `_`, `@`, or `-`; invalid input returns `400 Bad Request` without echoing the supplied value.

For the remaining command-line examples, capture the token with `jq`:

```bash
ACCESS_TOKEN="$(curl --silent --show-error --fail-with-body \
  --request POST http://localhost:9000/api/v1/tokens \
  --header 'Accept: application/json' \
  --header 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'subject=alice' \
  | jq --raw-output '.access_token')"
```

### Read the public JWKS

```bash
curl --silent --show-error --fail-with-body \
  http://localhost:9000/oauth2/jwks \
  | jq .
```

The `application/jwk-set+json` response contains the current RSA public key with `kid`, `use=sig`, `alg=RS256`, modulus `n`, and exponent `e`. It never contains private RSA parameters such as `d`, `p`, `q`, `dp`, `dq`, or `qi`.

### Call HelloWorld

```bash
curl --silent --show-error --fail-with-body \
  http://localhost:8080/api/v1/hello \
  --header 'Accept: application/json' \
  --header "Authorization: Bearer ${ACCESS_TOKEN}"
```

Response:

```json
{
  "message": "Hello, alice!"
}
```

A request without credentials is rejected before controller execution:

```bash
curl --include http://localhost:8080/api/v1/hello
```

It returns `401 Unauthorized` with `WWW-Authenticate: Bearer`. Invalid tokens return a generic `Bearer error="invalid_token"` challenge; validation details are deliberately omitted from the response and retained only in safe server-side warning logs.

## JWT profile and validation

Every issued value is a compact signed JWT with this private profile:

| Location | Member | Required value |
|---|---|---|
| JOSE header | `alg` | `RS256` |
| JOSE header | `typ` | `oauth-mini+jwt` |
| JOSE header | `kid` | Current signing-key identifier |
| Claim | `iss` | `http://localhost:9000` by default |
| Claim | `sub` | Normalized caller-supplied subject |
| Claim | `aud` | Contains `mini-resource-server` |
| Claim | `iat` | Issuance time |
| Claim | `exp` | Issuance time plus five minutes |
| Claim | `jti` | A new UUID for each token |

Before the controller executes, the Resource Server:

1. accepts only `RS256` and resolves the matching trusted public key by `kid`;
2. verifies the JWS signature;
3. requires the exact issuer, audience, and private `typ` value;
4. requires a nonblank `sub` represented as a JSON string, without coercing numbers, booleans, or structures into a principal;
5. requires `exp` and performs Spring Security's timestamp validation with its default 60-second clock-skew tolerance.

The configured issuer is a trust boundary and must match the JWT `iss` value byte-for-byte. In particular, adding a trailing slash to only one service causes authentication to fail.

## Postman demonstration

Import both committed files:

- `postman/OAuth2-Mini-Platform.postman_collection.json`
- `postman/Local.postman_environment.json`

Select **OAuth 2.0 Mini Platform - Local** as the active environment.

### Core flow

With both applications running, run the **Core flow** folder in order:

1. **Issue token** validates the response and stores `accessToken`.
2. **Call HelloWorld** sends that value as a bearer token and checks the greeting.
3. **Call HelloWorld without token** checks the `401` bearer challenge.
4. **Read JWKS** checks the public key and rejects private RSA members.

The folder can run as one uninterrupted sequence. If **Call HelloWorld** is sent individually before **Issue token**, its pre-request assertion explains which request must run first.

### Signing-key change

The **Key change** folder contains a required manual restart checkpoint and must not be run continuously:

1. Keep both applications running and send **1 — Issue token A and remember kid**. It stores token A's header `kid` as `previousKid`.
2. Leave the Resource Server running. Stop only the Authorization Server with `Ctrl+C` in terminal 1.
3. Restart only the Authorization Server with the same command:

   ```bash
   java -jar authorization-server/target/authorization-server-0.0.1-SNAPSHOT.jar
   ```

4. Wait for its application-started log or until this command succeeds:

   ```bash
   curl --fail http://localhost:9000/oauth2/jwks
   ```

5. Send **2 — Issue token B and assert new kid**. The script proves that `currentKid` is different from `previousKid` and stores token B.
6. Send **3 — Call HelloWorld with token B**. A `200` response proves that the still-running Resource Server discovered key B.

Do not resend request 1 after the restart: it intentionally resets the remembered state. If the Authorization Server was not restarted, request 2 fails with an actionable `kid did not change` assertion instead of allowing a false-positive demonstration.

Postman persists environment updates locally. The `accessToken` variable is marked secret, but that does not remove its value from an exported environment. Clear it before exporting, and do not commit an environment file containing a live token.

## Configuration

Local defaults are in each module's `application.yml`:

| Property | Default | Constraint/purpose |
|---|---|---|
| Authorization Server `server.port` | `9000` | Local issuer port |
| `application.security.issuer` | `http://localhost:9000` | Absolute HTTP(S) origin; identical on both services |
| `application.security.audience` | `mini-resource-server` | Required JWT audience; identical on both services |
| `application.security.token-type` | `oauth-mini+jwt` | Pinned private JWT type; identical on both services |
| `application.security.access-token-ttl` | `5m` | Whole seconds, from 1 second through 15 minutes |
| Authorization Server `server.tomcat.max-http-form-post-size` | `16KB` | Bounds form parsing before subject validation |
| `application.security.jwk-set-uri` | `http://localhost:9000/oauth2/jwks` | Trusted startup configuration, never request input |
| `application.security.jwks-connect-timeout` | `2s` | Resource Server JWKS connection bound; maximum 10 seconds |
| `application.security.jwks-read-timeout` | `2s` | Resource Server JWKS read bound; maximum 10 seconds |

Configuration is validated during startup. If ports or public addresses change, update the Authorization Server issuer and the Resource Server's issuer and JWKS URI together.

## Security decisions

This is a scoped security review, not a claim of OWASP certification.

| OWASP API Security risk | Project treatment |
|---|---|
| API1 Broken Object Level Authorization | No object or object identifier is exposed; HelloWorld uses the already validated principal |
| API2 Broken Authentication | Signature, algorithm, type, issuer, audience, subject, expiry, and key trust are validated before controller execution |
| API3 Broken Object Property Level Authorization | Fixed immutable response records; no generic entity binding or mass assignment |
| API4 Unrestricted Resource Consumption | 16 KB form limit, 100-character subject limit, bounded responses, and 2-second JWKS timeouts |
| API5 Broken Function Level Authorization | Exact method/path allowlists and default-deny security chains |
| API6 Unrestricted Access to Sensitive Business Flows | The unauthenticated minting endpoint is explicitly identified as a residual specification risk |
| API7 Server-Side Request Forgery | JWKS URI comes only from validated startup configuration; redirects are disabled |
| API8 Security Misconfiguration | Stateless services, startup validation, no Basic/form login, no server session, sanitized errors |
| API9 Improper Inventory Management | Complete three-endpoint surface documented; framework metadata endpoint shadowed and denied |
| API10 Unsafe Consumption of APIs | Trusted JWKS origin, strict timeouts, no redirects, and established JOSE parsing/validation libraries |

Additional controls:

- The Authorization Server generates one 2048-bit RSA key pair per process and retains the private key only in memory.
- The JWKS serializes a public-only JWK.
- Both services are stateless and deny unspecified routes. CSRF is disabled because authentication never relies on browser cookies.
- Subjects are normalized and allowlisted; query strings on the token route are rejected.
- Token responses are non-cacheable, and bearer tokens are accepted only through the `Authorization` header.
- Authentication responses are generic. Logs contain lifecycle information, token `jti` values, expiry instants, public `kid` values, and normalized failure reasons—not tokens, authorization headers, private keys, or subjects.
- JWT payloads are signed but not encrypted and are readable by their holder. Do not add secrets or unnecessary personal data to claims.
- HTTPS is mandatory anywhere outside this local demonstration. Bearer-token possession is sufficient for use, so transport protection is essential.

## Protocol boundary

The implementation uses these standards for the behavior in scope:

- [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750.html): bearer-token transport and `WWW-Authenticate` challenges
- [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.html): compact JWS signing and verification
- [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517.html): public JWK/JWKS representation and `kid` selection
- [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html): the registered `RS256` algorithm
- [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519.html): registered JWT claims
- [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html): algorithm restriction, explicit audience and issuer validation, and mutually exclusive token typing

[RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html) supplies the Authorization Server, Resource Server, access-token response, and bearer-token architectural vocabulary. This project does **not** claim RFC 6749 token-endpoint conformance because the specified request has no grant, `grant_type`, client authentication, or resource-owner authorization.

The JWT also does **not** claim [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068.html) conformance. It intentionally uses the private type `oauth-mini+jwt`, not `at+jwt`, and has no `client_id` because client registration is outside the specification.

## Key lifecycle and JWKS availability

Each Authorization Server process owns one ephemeral key. Restarting it immediately replaces key A with key B; the published JWKS contains only B. This is sufficient to demonstrate new-key discovery but is not a production rotation strategy.

The Resource Server loads JWKS lazily and caches public keys using Spring Security/Nimbus defaults:

- a token whose trusted public key is already cached may remain verifiable while the Authorization Server is unavailable;
- a request that requires a JWKS fetch or refresh cannot be authenticated while the endpoint is unavailable and receives the same generic `401 invalid_token` response;
- the HTTP connection and read waits are bounded to two seconds each;
- an unknown `kid` triggers JWKS refresh, which is how token B is accepted without restarting the Resource Server;
- after the JWKS refreshes to a set containing only key B, a still-unexpired token A may stop validating. No old-key overlap is promised.

The Resource Server intentionally does not turn a JWKS dependency failure into `503 Service Unavailable`; it treats the unresolved signing key as an authentication failure. Server-side logs retain the diagnostic reason while the client receives a uniform challenge.

## Known limitations and residual risks

These choices satisfy the exercise and must not be used as defaults for a public authorization system:

- Anyone who can reach the token endpoint can choose a subject and mint a token. A real issuer must authenticate and authorize the user or client.
- There is no rate limiting. Repeated requests can consume signing resources, and repeated oversized form submissions can create noisy container error logs even though Tomcat rejects them.
- There is no persistent key store, secure key-management service, rotation overlap, revocation, introspection, or token denylist. The five-minute lifetime only limits the exposure window.
- Restarting the Authorization Server loses the old private key. Old-token acceptance depends on the Resource Server's cache state and is not guaranteed.
- A JWKS outage can make uncached or new-key tokens unusable and is surfaced to clients as `401`, not `503`.
- Local HTTP exists only for reproducibility. Use HTTPS, appropriate network controls, authenticated token issuance, rate limits, persistent protected keys, observability, and a deliberate rotation policy outside this exercise.

## Repository layout

```text
.
├── authorization-server/   # JWT issuer and public JWKS, port 9000
├── resource-server/        # JWT validation and HelloWorld, port 8080
├── postman/                # Collection and token-free local environment
├── pom.xml                 # Java 21 multi-module Maven build
└── README.md
```

The detailed design and acceptance criteria are recorded in [`OAuth2-Mini-Platform-Implementation-Plan.md`](OAuth2-Mini-Platform-Implementation-Plan.md).
