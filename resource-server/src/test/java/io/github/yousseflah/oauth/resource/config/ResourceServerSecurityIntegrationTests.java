package io.github.yousseflah.oauth.resource.config;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.UUID;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.PlainHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.matchesPattern;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class ResourceServerSecurityIntegrationTests {

    private static final String AUDIENCE = "mini-resource-server";
    private static final String TOKEN_TYPE = "oauth-mini+jwt";
    private static final RSAKey TRUSTED_KEY = generateRsaKey();
    private static final RSAKey UNTRUSTED_KEY = generateRsaKey();
    private static final JwksTestServer JWKS_SERVER = JwksTestServer.start(TRUSTED_KEY.toPublicJWK());

    private final MockMvc mockMvc;

    @Autowired
    ResourceServerSecurityIntegrationTests(MockMvc mockMvc) {
        this.mockMvc = mockMvc;
    }

    @DynamicPropertySource
    static void registerSecurityProperties(DynamicPropertyRegistry registry) {
        registry.add("application.security.issuer", () -> JWKS_SERVER.issuer().toString());
        registry.add("application.security.jwk-set-uri", () -> JWKS_SERVER.jwkSetUri().toString());
    }

    @AfterAll
    static void stopJwksServer() {
        JWKS_SERVER.close();
    }

    @Test
    void returnsGreetingForAuthenticatedSubject() throws Exception {
        mockMvc.perform(get("/api/v1/hello")
                        .header(HttpHeaders.AUTHORIZATION, validBearerAuthorization("alice"))
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.message").value("Hello, alice!"));
    }

    @Test
    void rejectsMissingBearerTokenWithChallenge() throws Exception {
        mockMvc.perform(get("/api/v1/hello").accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(
                        HttpHeaders.WWW_AUTHENTICATE,
                        matchesPattern("^Bearer(?:\\s.+)?$")));
    }

    @Test
    void rejectsUnknownRoutesWithoutDisclosingWhetherTheyExist() throws Exception {
        mockMvc.perform(get("/api/v1/unknown").accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(
                        HttpHeaders.WWW_AUTHENTICATE,
                        matchesPattern("^Bearer(?:\\s.+)?$")));
    }

    @Test
    void deniesUnknownRoutesForAuthenticatedRequests() throws Exception {
        mockMvc.perform(get("/api/v1/unknown")
                        .header(HttpHeaders.AUTHORIZATION, validBearerAuthorization("alice"))
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isForbidden());
    }

    @Test
    void rejectsMalformedToken() throws Exception {
        assertInvalidTokenRejected("not-a-jwt");
    }

    @Test
    void rejectsTokenWithTamperedSignature() throws Exception {
        assertInvalidTokenRejected(tamperSignature(validToken("alice")));
    }

    @Test
    void rejectsTokenSignedByUntrustedKey() throws Exception {
        var token = sign(validClaims("alice").build(), rsaHeader(UNTRUSTED_KEY, TOKEN_TYPE), UNTRUSTED_KEY);

        assertInvalidTokenRejected(token);
    }

    @Test
    void rejectsTokenExpiredOutsideAllowedClockSkew() throws Exception {
        var now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        var claims = validClaims("alice")
                .issueTime(Date.from(now.minus(Duration.ofMinutes(5))))
                .expirationTime(Date.from(now.minus(Duration.ofMinutes(2))))
                .build();

        assertInvalidTokenRejected(sign(claims, rsaHeader(TRUSTED_KEY, TOKEN_TYPE), TRUSTED_KEY));
    }

    @Test
    void rejectsTokenWithWrongType() throws Exception {
        var token = sign(validClaims("alice").build(), rsaHeader(TRUSTED_KEY, "JWT"), TRUSTED_KEY);

        assertInvalidTokenRejected(token);
    }

    @Test
    void rejectsTokenWithMissingType() throws Exception {
        var token = sign(validClaims("alice").build(), rsaHeaderWithoutType(TRUSTED_KEY), TRUSTED_KEY);

        assertInvalidTokenRejected(token);
    }

    @Test
    void rejectsTokenWithWrongIssuer() throws Exception {
        var claims = validClaims("alice")
                .issuer("https://untrusted.example")
                .build();

        assertInvalidTokenRejected(sign(claims, rsaHeader(TRUSTED_KEY, TOKEN_TYPE), TRUSTED_KEY));
    }

    @Test
    void rejectsTokenWithWrongAudience() throws Exception {
        var claims = validClaims("alice")
                .audience("another-resource-server")
                .build();

        assertInvalidTokenRejected(sign(claims, rsaHeader(TRUSTED_KEY, TOKEN_TYPE), TRUSTED_KEY));
    }

    @Test
    void rejectsUnsecuredToken() throws Exception {
        var header = new PlainHeader.Builder()
                .type(new JOSEObjectType(TOKEN_TYPE))
                .build();
        var token = new PlainJWT(header, validClaims("alice").build()).serialize();

        assertInvalidTokenRejected(token);
    }

    @Test
    void rejectsHs256TokenUsingRsaPublicKeyAsHmacSecret() throws Exception {
        var header = new JWSHeader.Builder(JWSAlgorithm.HS256)
                .type(new JOSEObjectType(TOKEN_TYPE))
                .keyID(TRUSTED_KEY.getKeyID())
                .build();
        var signedJwt = new SignedJWT(header, validClaims("alice").build());
        signedJwt.sign(new MACSigner(TRUSTED_KEY.toRSAPublicKey().getEncoded()));

        assertInvalidTokenRejected(signedJwt.serialize());
    }

    @Test
    void deniesUnlistedMethodsForAuthenticatedRequests() throws Exception {
        mockMvc.perform(post("/api/v1/hello")
                        .header(HttpHeaders.AUTHORIZATION, validBearerAuthorization("alice"))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isForbidden());
    }

    private void assertInvalidTokenRejected(String token) throws Exception {
        mockMvc.perform(get("/api/v1/hello")
                        .header(HttpHeaders.AUTHORIZATION, bearerAuthorization(token))
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(
                        HttpHeaders.WWW_AUTHENTICATE,
                        "Bearer error=\"invalid_token\""))
                .andExpect(content().string(""));
    }

    private static String validBearerAuthorization(String subject) throws JOSEException {
        return bearerAuthorization(validToken(subject));
    }

    private static String validToken(String subject) throws JOSEException {
        return sign(validClaims(subject).build(), rsaHeader(TRUSTED_KEY, TOKEN_TYPE), TRUSTED_KEY);
    }

    private static JWTClaimsSet.Builder validClaims(String subject) {
        var now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        return new JWTClaimsSet.Builder()
                .issuer(JWKS_SERVER.issuer().toString())
                .subject(subject)
                .audience(AUDIENCE)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(Duration.ofMinutes(5))))
                .jwtID(UUID.randomUUID().toString());
    }

    private static JWSHeader rsaHeader(RSAKey key, String tokenType) {
        return new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(new JOSEObjectType(tokenType))
                .keyID(key.getKeyID())
                .build();
    }

    private static JWSHeader rsaHeaderWithoutType(RSAKey key) {
        return new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(key.getKeyID())
                .build();
    }

    private static String sign(JWTClaimsSet claims, JWSHeader header, RSAKey key) throws JOSEException {
        var signedJwt = new SignedJWT(header, claims);
        signedJwt.sign(new RSASSASigner(key));
        return signedJwt.serialize();
    }

    private static String bearerAuthorization(String token) {
        return "Bearer " + token;
    }

    private static String tamperSignature(String token) {
        var signatureStart = token.lastIndexOf('.') + 1;
        var originalCharacter = token.charAt(signatureStart);
        var replacementCharacter = originalCharacter == 'A' ? 'B' : 'A';
        return token.substring(0, signatureStart)
                + replacementCharacter
                + token.substring(signatureStart + 1);
    }

    private static RSAKey generateRsaKey() {
        try {
            return new RSAKeyGenerator(2048)
                    .keyUse(KeyUse.SIGNATURE)
                    .algorithm(JWSAlgorithm.RS256)
                    .keyID(UUID.randomUUID().toString())
                    .generate();
        } catch (JOSEException exception) {
            throw new IllegalStateException("Failed to create an RSA test key", exception);
        }
    }
}
