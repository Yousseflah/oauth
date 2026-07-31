package io.github.yousseflah.oauth.resource.config;

import java.io.IOException;
import java.util.regex.Pattern;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.web.AuthenticationEntryPoint;

final class NonAdvertisingBearerTokenAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private static final Pattern RESOURCE_METADATA_PARAMETER =
            Pattern.compile("(?:,\\s*|\\s+)resource_metadata=\"[^\"]*\"$");

    private final BearerTokenAuthenticationEntryPoint delegate = new BearerTokenAuthenticationEntryPoint();

    @Override
    public void commence(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException authenticationException) throws IOException, ServletException {
        delegate.commence(request, response, authenticationException);

        var challenge = response.getHeader(HttpHeaders.WWW_AUTHENTICATE);
        if (challenge != null) {
            response.setHeader(HttpHeaders.WWW_AUTHENTICATE, removeResourceMetadataParameter(challenge));
        }
    }

    private static String removeResourceMetadataParameter(String challenge) {
        return RESOURCE_METADATA_PARAMETER.matcher(challenge).replaceFirst("");
    }
}
