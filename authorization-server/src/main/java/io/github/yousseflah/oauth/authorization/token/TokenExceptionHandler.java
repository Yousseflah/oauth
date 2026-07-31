package io.github.yousseflah.oauth.authorization.token;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice(assignableTypes = TokenController.class)
final class TokenExceptionHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(TokenExceptionHandler.class);
    private static final String PROBLEM_TITLE = "Invalid token request";

    @ExceptionHandler(InvalidSubjectException.class)
    ProblemDetail handleInvalidSubject(InvalidSubjectException exception) {
        LOGGER.warn("Rejected token request because subject validation failed");
        return badRequest(exception.getMessage());
    }

    @ExceptionHandler(MissingServletRequestParameterException.class)
    ProblemDetail handleMissingSubject(MissingServletRequestParameterException exception) {
        LOGGER.warn("Rejected token request because required parameter={} is missing", exception.getParameterName());
        return badRequest("subject is required");
    }

    private static ProblemDetail badRequest(String detail) {
        var problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, detail);
        problemDetail.setTitle(PROBLEM_TITLE);
        return problemDetail;
    }
}
