package io.github.yousseflah.oauth.authorization.token;

final class InvalidSubjectException extends IllegalArgumentException {

    InvalidSubjectException() {
        super("subject must contain 1 to 100 letters, digits, '.', '_', '@', or '-'");
    }
}
