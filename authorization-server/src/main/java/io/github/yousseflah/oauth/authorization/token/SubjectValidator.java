package io.github.yousseflah.oauth.authorization.token;

import java.util.regex.Pattern;

import org.springframework.stereotype.Component;

@Component
final class SubjectValidator {

    private static final Pattern ALLOWED_SUBJECT = Pattern.compile("[A-Za-z0-9._@-]{1,100}");

    String normalize(String subject) {
        if (subject == null) {
            throw new InvalidSubjectException();
        }

        var normalizedSubject = subject.strip();
        if (!ALLOWED_SUBJECT.matcher(normalizedSubject).matches()) {
            throw new InvalidSubjectException();
        }

        return normalizedSubject;
    }
}
