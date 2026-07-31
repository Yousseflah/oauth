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

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class SigningKeyChangeIntegrationTests {

    private static final String AUDIENCE = "mini-resource-server";
    private static final String TOKEN_TYPE = "oauth-mini+jwt";
    private static final RSAKey KEY_A = generateRsaKey("key-a");
    private static final RSAKey KEY_B = generateRsaKey("key-b");
    private static final JwksTestServer JWKS_SERVER = JwksTestServer.start(KEY_A.toPublicJWK());

    private final MockMvc mockMvc;

    @Autowired
    SigningKeyChangeIntegrationTests(MockMvc mockMvc) {
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
    void acceptsTokenSignedByNewKeyWithoutRestartingResourceServer() throws Exception {
        assertThat(KEY_B.getKeyID()).isNotEqualTo(KEY_A.getKeyID());

        assertGreeting(signToken(KEY_A, "alice"), "Hello, alice!");
        var requestsAfterKeyA = JWKS_SERVER.successfulRequestCount();
        assertThat(requestsAfterKeyA).isPositive();

        JWKS_SERVER.publish(KEY_B.toPublicJWK());

        assertGreeting(signToken(KEY_B, "bob"), "Hello, bob!");
        assertThat(JWKS_SERVER.successfulRequestCount()).isGreaterThan(requestsAfterKeyA);
    }

    private void assertGreeting(String token, String expectedMessage) throws Exception {
        mockMvc.perform(get("/api/v1/hello")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.message").value(expectedMessage));
    }

    private static String signToken(RSAKey signingKey, String subject) throws JOSEException {
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
                .keyID(signingKey.getKeyID())
                .build();
        var signedJwt = new SignedJWT(header, claims);
        signedJwt.sign(new RSASSASigner(signingKey));
        return signedJwt.serialize();
    }

    private static RSAKey generateRsaKey(String keyId) {
        try {
            return new RSAKeyGenerator(2048)
                    .keyUse(KeyUse.SIGNATURE)
                    .algorithm(JWSAlgorithm.RS256)
                    .keyID(keyId)
                    .generate();
        } catch (JOSEException exception) {
            throw new IllegalStateException("Failed to create an RSA test key", exception);
        }
    }
}
