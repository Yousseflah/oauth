package io.github.yousseflah.oauth.resource.config;

import java.time.Instant;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;

import static org.assertj.core.api.Assertions.assertThat;

class AudienceValidatorTest {

    private static final String REQUIRED_AUDIENCE = "mini-resource-server";

    private final AudienceValidator validator = new AudienceValidator(REQUIRED_AUDIENCE);

    @Test
    void acceptsTokenWhoseOnlyAudienceIsRequired() {
        var jwt = jwtBuilder().claim(JwtClaimNames.AUD, List.of(REQUIRED_AUDIENCE)).build();

        assertThat(validator.validate(jwt).hasErrors()).isFalse();
    }

    @Test
    void acceptsTokenListingRequiredAudienceAmongOthers() {
        var jwt = jwtBuilder()
                .claim(JwtClaimNames.AUD, List.of("another-resource-server", REQUIRED_AUDIENCE))
                .build();

        assertThat(validator.validate(jwt).hasErrors()).isFalse();
    }

    @Test
    void rejectsTokenWithoutAudienceClaim() {
        assertInvalidAudience(jwtBuilder().build());
    }

    @ParameterizedTest
    @MethodSource("invalidAudiences")
    void rejectsTokenWithUnexpectedAudience(Object audience) {
        var jwt = jwtBuilder().claim(JwtClaimNames.AUD, audience).build();

        assertInvalidAudience(jwt);
    }

    private void assertInvalidAudience(Jwt jwt) {
        assertThat(validator.validate(jwt).getErrors())
                .singleElement()
                .extracting(error -> error.getErrorCode())
                .isEqualTo(OAuth2ErrorCodes.INVALID_TOKEN);
    }

    private static Stream<Object> invalidAudiences() {
        return Stream.of(
                List.of(),
                List.of("another-resource-server"),
                List.of("mini-resource-server-2"),
                "another-resource-server");
    }

    private static Jwt.Builder jwtBuilder() {
        var now = Instant.parse("2026-01-02T03:04:05Z");
        return Jwt.withTokenValue("test-token")
                .header("alg", "RS256")
                .issuer("http://localhost:9000")
                .subject("alice")
                .issuedAt(now)
                .expiresAt(now.plusSeconds(300));
    }
}
