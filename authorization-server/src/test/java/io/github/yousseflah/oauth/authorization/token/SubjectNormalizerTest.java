package io.github.yousseflah.oauth.authorization.token;

import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SubjectNormalizerTest {

    private final SubjectNormalizer subjectNormalizer = new SubjectNormalizer();

    @Test
    void trimsAndAcceptsAnAllowedSubject() {
        assertThat(subjectNormalizer.normalize("  alice.smith-1@example.com_  "))
                .isEqualTo("alice.smith-1@example.com_");
    }

    @Test
    void acceptsTheMaximumLength() {
        var subject = "a".repeat(100);

        assertThat(subjectNormalizer.normalize(subject)).isEqualTo(subject);
    }

    @ParameterizedTest
    @MethodSource("invalidSubjects")
    void rejectsMissingBlankOversizedOrDisallowedSubjects(String subject) {
        assertThatThrownBy(() -> subjectNormalizer.normalize(subject))
                .isInstanceOf(InvalidSubjectException.class)
                .hasMessage("subject must contain 1 to 100 letters, digits, '.', '_', '@', or '-'");
    }

    private static Stream<String> invalidSubjects() {
        return Stream.of(
                null,
                "",
                "   ",
                "a".repeat(101),
                "alice smith",
                "alice/bob",
                "álîce");
    }
}
