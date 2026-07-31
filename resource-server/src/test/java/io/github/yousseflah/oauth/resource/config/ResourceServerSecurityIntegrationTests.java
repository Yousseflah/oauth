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
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
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

import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.matchesPattern;
import static org.hamcrest.Matchers.not;
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
                        .header(HttpHeaders.AUTHORIZATION, bearerAuthorization("alice"))
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
                        allOf(
                                matchesPattern("^Bearer(?: .+)?$"),
                                not(containsString("error=")))));
    }

    @Test
    void deniesUnknownRoutesForAuthenticatedRequests() throws Exception {
        mockMvc.perform(get("/api/v1/unknown")
                        .header(HttpHeaders.AUTHORIZATION, bearerAuthorization("alice"))
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isForbidden());
    }

    @Test
    void deniesUnlistedMethodsForAuthenticatedRequests() throws Exception {
        mockMvc.perform(post("/api/v1/hello")
                        .header(HttpHeaders.AUTHORIZATION, bearerAuthorization("alice"))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isForbidden());
    }

    private static String bearerAuthorization(String subject) throws JOSEException {
        var now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        var claims = new JWTClaimsSet.Builder()
                .issuer(JWKS_SERVER.issuer().toString())
                .subject(subject)
                .audience(AUDIENCE)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(Duration.ofMinutes(5))))
                .jwtID(UUID.randomUUID().toString())
                .build();
        var header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(new JOSEObjectType(TOKEN_TYPE))
                .keyID(TRUSTED_KEY.getKeyID())
                .build();
        var signedJwt = new SignedJWT(header, claims);
        signedJwt.sign(new RSASSASigner(TRUSTED_KEY));
        return "Bearer " + signedJwt.serialize();
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
