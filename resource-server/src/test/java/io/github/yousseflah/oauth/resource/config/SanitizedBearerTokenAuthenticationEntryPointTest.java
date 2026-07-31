package io.github.yousseflah.oauth.resource.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(OutputCaptureExtension.class)
class SanitizedBearerTokenAuthenticationEntryPointTest {

    private final SanitizedBearerTokenAuthenticationEntryPoint entryPoint =
            new SanitizedBearerTokenAuthenticationEntryPoint();

    @Test
    void logsInvalidTokenReasonWhileExposingOnlyTheErrorCode(CapturedOutput output) throws Exception {
        var response = commence(new InvalidBearerTokenException("Token validation failed"));

        assertThat(response.getHeader(HttpHeaders.WWW_AUTHENTICATE))
                .isEqualTo("Bearer error=\"invalid_token\"");
        assertThat(output).contains("WARN", "Rejected bearer token: Token validation failed");
    }

    @Test
    void keepsSpringChallengeForBearerErrorsOtherThanInvalidToken(CapturedOutput output) throws Exception {
        var insufficientScope = new OAuth2AuthenticationException(
                new OAuth2Error(OAuth2ErrorCodes.INSUFFICIENT_SCOPE, "The token has insufficient scope", null));

        var response = commence(insufficientScope);

        assertThat(response.getHeader(HttpHeaders.WWW_AUTHENTICATE))
                .startsWith("Bearer")
                .contains(
                        "error=\"insufficient_scope\"",
                        "error_description=\"The token has insufficient scope\"");
        assertThat(output).doesNotContain("Rejected bearer token");
    }

    private MockHttpServletResponse commence(AuthenticationException authenticationException) throws Exception {
        var request = new MockHttpServletRequest("GET", "/api/v1/hello");
        var response = new MockHttpServletResponse();
        entryPoint.commence(request, response, authenticationException);
        return response;
    }
}
