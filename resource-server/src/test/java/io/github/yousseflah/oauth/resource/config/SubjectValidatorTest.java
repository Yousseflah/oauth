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

class SubjectValidatorTest {

    private final SubjectValidator validator = new SubjectValidator();

    @Test
    void acceptsNonblankStringSubject() {
        var result = validator.validate(jwtBuilder().subject("alice").build());

        assertThat(result.hasErrors()).isFalse();
    }

    @Test
    void rejectsMissingSubject() {
        assertInvalidSubject(jwtBuilder().build());
    }

    @ParameterizedTest
    @MethodSource("invalidSubjects")
    void rejectsBlankOrWrongTypedSubject(Object subject) {
        var jwt = jwtBuilder().claim(JwtClaimNames.SUB, subject).build();

        assertInvalidSubject(jwt);
    }

    private void assertInvalidSubject(Jwt jwt) {
        assertThat(validator.validate(jwt).getErrors())
                .singleElement()
                .extracting(error -> error.getErrorCode())
                .isEqualTo(OAuth2ErrorCodes.INVALID_TOKEN);
    }

    private static Stream<Object> invalidSubjects() {
        return Stream.of("", " ", 123, 12.5, true, List.of("alice", "bob"));
    }

    private static Jwt.Builder jwtBuilder() {
        var now = Instant.parse("2026-01-02T03:04:05Z");
        return Jwt.withTokenValue("test-token")
                .header("alg", "RS256")
                .issuer("http://localhost:9000")
                .issuedAt(now)
                .expiresAt(now.plusSeconds(300));
    }
}
