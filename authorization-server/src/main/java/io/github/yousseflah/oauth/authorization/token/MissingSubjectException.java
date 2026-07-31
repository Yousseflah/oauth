package io.github.yousseflah.oauth.authorization.token;

final class MissingSubjectException extends IllegalArgumentException {

    MissingSubjectException() {
        super("subject is required");
    }
}
