package io.github.yousseflah.oauth.resource.config;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;

class NonAdvertisingBearerTokenAuthenticationEntryPointTest {

    private final NonAdvertisingBearerTokenAuthenticationEntryPoint entryPoint =
            new NonAdvertisingBearerTokenAuthenticationEntryPoint();

    @Test
    void removesResourceMetadataFromMissingCredentialsChallenge() throws Exception {
        var response = commence(new AuthenticationCredentialsNotFoundException("Bearer token is required"));

        assertThat(response.getHeader(HttpHeaders.WWW_AUTHENTICATE)).isEqualTo("Bearer");
    }

    @Test
    void preservesBearerErrorWhileRemovingResourceMetadata() throws Exception {
        var response = commence(new InvalidBearerTokenException("Token validation failed"));

        assertThat(response.getHeader(HttpHeaders.WWW_AUTHENTICATE))
                .startsWith("Bearer error=\"invalid_token\"")
                .contains("error_description=", "error_uri=")
                .doesNotContain("resource_metadata")
                .doesNotMatch(".*[,\\s]$");
    }

    private MockHttpServletResponse commence(AuthenticationException authenticationException) throws Exception {
        var request = new MockHttpServletRequest("GET", "/api/v1/hello");
        var response = new MockHttpServletResponse();
        entryPoint.commence(
                request,
                response,
                authenticationException);
        return response;
    }
}
