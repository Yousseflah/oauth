package io.github.yousseflah.oauth.authorization.token;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice(assignableTypes = TokenController.class)
final class TokenExceptionHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(TokenExceptionHandler.class);
    private static final String PROBLEM_TITLE = "Invalid token request";

    @ExceptionHandler({
        InvalidSubjectException.class,
        MissingSubjectException.class,
        QueryParametersNotAllowedException.class
    })
    ProblemDetail handleInvalidTokenRequest(IllegalArgumentException exception) {
        // Every allowlisted exception has a fixed message that never includes caller input.
        LOGGER.warn("Rejected token request: {}", exception.getMessage());
        return badRequest(exception.getMessage());
    }

    private static ProblemDetail badRequest(String detail) {
        var problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, detail);
        problemDetail.setTitle(PROBLEM_TITLE);
        return problemDetail;
    }
}
