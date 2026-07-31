package io.github.yousseflah.oauth.resource.config;

import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.web.AuthenticationEntryPoint;

final class SanitizedBearerTokenAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(SanitizedBearerTokenAuthenticationEntryPoint.class);
    private static final String INVALID_TOKEN_CHALLENGE = "Bearer error=\"invalid_token\"";

    private final BearerTokenAuthenticationEntryPoint delegate = new BearerTokenAuthenticationEntryPoint();

    @Override
    public void commence(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException authenticationException) throws IOException, ServletException {
        delegate.commence(request, response, authenticationException);

        // Keep Spring's standard discovery challenge, but never expose token-validation diagnostics.
        if (authenticationException instanceof OAuth2AuthenticationException oauth2Exception
                && OAuth2ErrorCodes.INVALID_TOKEN.equals(oauth2Exception.getError().getErrorCode())) {
            LOGGER.warn("Rejected bearer token: {}", oauth2Exception.getError().getDescription());
            response.setHeader(HttpHeaders.WWW_AUTHENTICATE, INVALID_TOKEN_CHALLENGE);
        }
    }
}
