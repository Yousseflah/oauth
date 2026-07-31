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
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest
class JwtDecoderIntegrationTests {

    private static final String AUDIENCE = "mini-resource-server";
    private static final String TOKEN_TYPE = "oauth-mini+jwt";
    private static final RSAKey TRUSTED_KEY = generateRsaKey();
    private static final JwksTestServer JWKS_SERVER = JwksTestServer.start(TRUSTED_KEY.toPublicJWK());

    private final JwtDecoder jwtDecoder;

    @Autowired
    JwtDecoderIntegrationTests(JwtDecoder jwtDecoder) {
        this.jwtDecoder = jwtDecoder;
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
    void decodesTokenMatchingTheCompletePrivateProfile() throws JOSEException {
        var token = sign(validClaims().build(), TOKEN_TYPE);

        var decoded = jwtDecoder.decode(token);

        assertThat(decoded.getSubject()).isEqualTo("alice");
        assertThat(decoded.getIssuer().toString()).isEqualTo(JWKS_SERVER.issuer().toString());
        assertThat(decoded.getAudience()).contains(AUDIENCE);
        assertThat(decoded.getHeaders()).containsEntry("typ", TOKEN_TYPE);
    }

    @Test
    void rejectsWrongTokenType() throws JOSEException {
        var token = sign(validClaims().build(), "JWT");

        assertRejected(token);
    }

    @Test
    void rejectsWrongIssuer() throws JOSEException {
        var token = sign(validClaims().issuer("https://untrusted.example").build(), TOKEN_TYPE);

        assertRejected(token);
    }

    @Test
    void rejectsWrongAudience() throws JOSEException {
        var token = sign(validClaims().audience("another-resource-server").build(), TOKEN_TYPE);

        assertRejected(token);
    }

    @Test
    void rejectsMissingAudience() throws JOSEException {
        var token = sign(baseClaims().subject("alice").build(), TOKEN_TYPE);

        assertRejected(token);
    }

    @Test
    void rejectsMissingSubject() throws JOSEException {
        var token = sign(baseClaims().audience(AUDIENCE).build(), TOKEN_TYPE);

        assertRejected(token);
    }

    @Test
    void rejectsBlankSubject() throws JOSEException {
        var token = sign(validClaims().subject(" ").build(), TOKEN_TYPE);

        assertRejected(token);
    }

    @Test
    void rejectsExpiredTokenOutsideTheAllowedClockSkew() throws JOSEException {
        var now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        var token = sign(validClaims()
                .issueTime(Date.from(now.minus(Duration.ofMinutes(5))))
                .expirationTime(Date.from(now.minus(Duration.ofMinutes(2))))
                .build(), TOKEN_TYPE);

        assertRejected(token);
    }

    @Test
    void rejectsMissingExpiration() throws JOSEException {
        var now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        var claims = new JWTClaimsSet.Builder()
                .issuer(JWKS_SERVER.issuer().toString())
                .subject("alice")
                .audience(AUDIENCE)
                .issueTime(Date.from(now))
                .jwtID(UUID.randomUUID().toString())
                .build();
        var token = sign(claims, TOKEN_TYPE);

        assertRejected(token);
    }

    private void assertRejected(String token) {
        assertThatThrownBy(() -> jwtDecoder.decode(token))
                .isInstanceOf(JwtValidationException.class);
    }

    private static JWTClaimsSet.Builder validClaims() {
        return baseClaims()
                .subject("alice")
                .audience(AUDIENCE);
    }

    private static JWTClaimsSet.Builder baseClaims() {
        var now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        return new JWTClaimsSet.Builder()
                .issuer(JWKS_SERVER.issuer().toString())
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(Duration.ofMinutes(5))))
                .jwtID(UUID.randomUUID().toString());
    }

    private static String sign(JWTClaimsSet claims, String tokenType) throws JOSEException {
        var header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(new JOSEObjectType(tokenType))
                .keyID(TRUSTED_KEY.getKeyID())
                .build();
        var signedJwt = new SignedJWT(header, claims);
        signedJwt.sign(new RSASSASigner(TRUSTED_KEY));
        return signedJwt.serialize();
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
