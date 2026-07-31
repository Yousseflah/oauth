package io.github.yousseflah.oauth.authorization.token;

final class QueryParametersNotAllowedException extends IllegalArgumentException {

    QueryParametersNotAllowedException() {
        super("query parameters are not allowed; submit subject in the form body");
    }
}
