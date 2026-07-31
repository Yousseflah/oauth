package io.github.yousseflah.oauth.resource.config;

import java.text.ParseException;
import java.time.Instant;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.MACSigner;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class StrictSubjectJwtDecoderTest {

    private static final byte[] TEST_SECRET = "strict-subject-decoder-test-secret-key".getBytes();

    @Test
    void returnsDelegateResultWhenSubjectClaimIsAString() throws JOSEException {
        var delegateResult = decodedJwt();
        var decoder = new StrictSubjectJwtDecoder(token -> delegateResult);

        var decoded = decoder.decode(signedPayload("{\"sub\":\"alice\"}"));

        assertThat(decoded).isSameAs(delegateResult);
    }

    @Test
    void rejectsNumericSubjectClaimThatSpringWouldCoerceToAString() throws JOSEException {
        var decoder = new StrictSubjectJwtDecoder(token -> decodedJwt());

        assertThatThrownBy(() -> decoder.decode(signedPayload("{\"sub\":123}")))
                .isInstanceOf(BadJwtException.class)
                .hasMessageContaining("The token subject must be a string");
    }

    @Test
    void rejectsMissingSubjectClaim() throws JOSEException {
        var decoder = new StrictSubjectJwtDecoder(token -> decodedJwt());

        assertThatThrownBy(() -> decoder.decode(signedPayload("{\"iss\":\"http://localhost:9000\"}")))
                .isInstanceOf(BadJwtException.class)
                .hasMessageContaining("The token subject must be a string");
    }

    @Test
    void rejectsTokenWhosePayloadIsNotAJsonObject() throws JOSEException {
        var decoder = new StrictSubjectJwtDecoder(token -> decodedJwt());

        assertThatThrownBy(() -> decoder.decode(signedPayload("not-a-json-object")))
                .isInstanceOf(BadJwtException.class)
                .hasMessageContaining("The token subject must be a string");
    }

    // Defensive only: the configured Nimbus decoder rejects an unparseable token before this
    // decoder re-reads it, but JWSObject.parse declares a checked ParseException that must be
    // handled. HTTP-level malformed-token behaviour is proven by ResourceServerSecurityIntegrationTests.
    @Test
    void rejectsTokenThatCannotBeParsedAsCompactJws() {
        var decoder = new StrictSubjectJwtDecoder(token -> decodedJwt());

        assertThatThrownBy(() -> decoder.decode("not-a-jwt"))
                .isInstanceOf(BadJwtException.class)
                .hasMessageContaining("Malformed token")
                .hasCauseInstanceOf(ParseException.class);
    }

    private static String signedPayload(String payload) throws JOSEException {
        var jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.HS256), new Payload(payload));
        jwsObject.sign(new MACSigner(TEST_SECRET));
        return jwsObject.serialize();
    }

    private static Jwt decodedJwt() {
        var now = Instant.parse("2026-01-02T03:04:05Z");
        return Jwt.withTokenValue("test-token")
                .header("alg", "RS256")
                .subject("alice")
                .issuedAt(now)
                .expiresAt(now.plusSeconds(300))
                .build();
    }
}
