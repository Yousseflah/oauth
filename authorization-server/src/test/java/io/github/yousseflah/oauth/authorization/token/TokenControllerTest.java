package io.github.yousseflah.oauth.authorization.token;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;

import io.github.yousseflah.oauth.authorization.config.AuthorizationSecurityProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TokenControllerTest {

    private static final Instant CLOCK_INSTANT = Instant.parse("2026-01-02T03:04:05Z");
    private static final Duration ACCESS_TOKEN_TTL = Duration.ofMinutes(5);

    private CapturingJwtEncoder jwtEncoder;
    private TokenController tokenController;

    @BeforeEach
    void setUpController() {
        jwtEncoder = new CapturingJwtEncoder();
        var properties = new AuthorizationSecurityProperties(
                URI.create("http://localhost:9000"),
                "mini-resource-server",
                "oauth-mini+jwt",
                ACCESS_TOKEN_TTL);
        var tokenService = new TokenService(
                jwtEncoder,
                properties,
                new SubjectNormalizer(),
                Clock.fixed(CLOCK_INSTANT, ZoneOffset.UTC));
        tokenController = new TokenController(tokenService);
    }

    @Test
    void mapsIssuedTokenToDocumentedResponse() {
        var response = tokenController.issueToken(new MockHttpServletRequest(), "alice");

        assertThat(response.accessToken()).isEqualTo("encoded-token-1");
        assertThat(response.tokenType()).isEqualTo("Bearer");
        assertThat(response.expiresInSeconds()).isEqualTo(ACCESS_TOKEN_TTL.toSeconds());
    }

    @Test
    void rejectsAQueryStringEvenWhenItCarriesAValidSubject() {
        var request = new MockHttpServletRequest();
        request.setQueryString("subject=alice");

        assertThatThrownBy(() -> tokenController.issueToken(request, "alice"))
                .isInstanceOf(QueryParametersNotAllowedException.class)
                .hasMessageContaining("submit subject in the form body");
        assertThat(jwtEncoder.encodingCount()).isZero();
    }

    @Test
    void rejectsAnUnrelatedQueryStringBeforeValidatingTheSubject() {
        var request = new MockHttpServletRequest();
        request.setQueryString("unrelated=value");

        assertThatThrownBy(() -> tokenController.issueToken(request, null))
                .isInstanceOf(QueryParametersNotAllowedException.class);
        assertThat(jwtEncoder.encodingCount()).isZero();
    }

    @Test
    void rejectsAMissingSubjectBeforeEncoding() {
        assertThatThrownBy(() -> tokenController.issueToken(new MockHttpServletRequest(), null))
                .isInstanceOf(MissingSubjectException.class)
                .hasMessage("subject is required");
        assertThat(jwtEncoder.encodingCount()).isZero();
    }

    private static final class CapturingJwtEncoder implements JwtEncoder {

        private final List<JwtEncoderParameters> capturedParameters = new ArrayList<>();

        @Override
        public Jwt encode(JwtEncoderParameters parameters) {
            capturedParameters.add(parameters);
            var claims = parameters.getClaims().getClaims();
            return new Jwt(
                    "encoded-token-" + capturedParameters.size(),
                    (Instant) claims.get("iat"),
                    (Instant) claims.get("exp"),
                    parameters.getJwsHeader().getHeaders(),
                    claims);
        }

        int encodingCount() {
            return capturedParameters.size();
        }
    }
}
