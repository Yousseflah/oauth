package io.github.yousseflah.oauth.authorization.token;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import io.github.yousseflah.oauth.authorization.config.AuthorizationProperties;
import io.github.yousseflah.oauth.authorization.jwk.EphemeralRsaKeyProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class TokenServiceTest {

    private static final Instant NOW = Instant.parse("2026-01-02T03:04:05Z");
    private static final Duration ACCESS_TOKEN_TTL = Duration.ofMinutes(5);

    private CapturingJwtEncoder jwtEncoder;
    private EphemeralRsaKeyProvider keyProvider;
    private TokenService tokenService;

    @BeforeAll
    void generateSigningKey() {
        keyProvider = new EphemeralRsaKeyProvider();
    }

    @BeforeEach
    void setUpTokenService() {
        jwtEncoder = new CapturingJwtEncoder();
        var properties = new AuthorizationProperties(
                URI.create("http://localhost:9000"),
                "mini-resource-server",
                "oauth-mini+jwt",
                ACCESS_TOKEN_TTL);
        var clock = Clock.fixed(NOW, ZoneOffset.UTC);
        tokenService = new TokenService(
                jwtEncoder,
                keyProvider,
                properties,
                new SubjectValidator(),
                clock);
    }

    @Test
    void createsRequiredHeadersClaimsAndLifetime() {
        var issuedToken = tokenService.issueToken("  alice@example.com  ");
        var parameters = jwtEncoder.lastParameters();
        var headers = parameters.getJwsHeader();
        var claims = parameters.getClaims();

        assertThat(issuedToken.accessToken()).isEqualTo("encoded-token-1");
        assertThat(issuedToken.expiresInSeconds()).isEqualTo(ACCESS_TOKEN_TTL.toSeconds());
        assertThat(headers.getAlgorithm()).isEqualTo(SignatureAlgorithm.RS256);
        assertThat(headers.getType()).isEqualTo("oauth-mini+jwt");
        assertThat(headers.getKeyId()).isEqualTo(keyProvider.publicJwk().getKeyID());
        assertThat(claims.getIssuer().toString()).isEqualTo("http://localhost:9000");
        assertThat(claims.getSubject()).isEqualTo("alice@example.com");
        assertThat(claims.getAudience()).containsExactly("mini-resource-server");
        assertThat(claims.getIssuedAt()).isEqualTo(NOW);
        assertThat(claims.getExpiresAt()).isEqualTo(NOW.plus(ACCESS_TOKEN_TTL));
        assertThat(claims.getId()).isNotBlank();
        assertThatCode(() -> UUID.fromString(claims.getId())).doesNotThrowAnyException();
    }

    @Test
    void createsAUniqueTokenIdentifierForEveryToken() {
        tokenService.issueToken("alice");
        tokenService.issueToken("alice");

        assertThat(jwtEncoder.lastTwoTokenIds()).doesNotHaveDuplicates();
    }

    @Test
    void rejectsInvalidSubjectBeforeEncoding() {
        var encodingCount = jwtEncoder.encodingCount();

        assertThatThrownBy(() -> tokenService.issueToken("alice smith"))
                .isInstanceOf(InvalidSubjectException.class);
        assertThat(jwtEncoder.encodingCount()).isEqualTo(encodingCount);
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

        JwtEncoderParameters lastParameters() {
            return capturedParameters.getLast();
        }

        List<String> lastTwoTokenIds() {
            return capturedParameters.reversed().stream()
                    .limit(2)
                    .map(parameters -> parameters.getClaims().getId())
                    .toList();
        }

        int encodingCount() {
            return capturedParameters.size();
        }
    }
}
