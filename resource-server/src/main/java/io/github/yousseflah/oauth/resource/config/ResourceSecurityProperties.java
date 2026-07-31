package io.github.yousseflah.oauth.resource.config;

import java.net.URI;
import java.time.Duration;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties("application.security")
record ResourceSecurityProperties(
        @NotNull URI issuer,
        @NotNull URI jwkSetUri,
        @NotNull @Size(max = 100) @Pattern(regexp = "\\S+") String audience,
        // Keep the private type visible in configuration, but pin it to prevent issuer/consumer drift.
        @NotNull @Pattern(regexp = "oauth-mini\\+jwt") String tokenType,
        @NotNull Duration jwksConnectTimeout,
        @NotNull Duration jwksReadTimeout) {

    private static final Duration MIN_HTTP_TIMEOUT = Duration.ofMillis(1);
    private static final Duration MAX_HTTP_TIMEOUT = Duration.ofSeconds(10);

    @AssertTrue(message = "must be an absolute HTTP or HTTPS origin URI without user info, path, query, or fragment")
    boolean isIssuerValid() {
        return isAbsoluteHttpUri(issuer)
                && (issuer.getRawPath() == null || issuer.getRawPath().isEmpty())
                && issuer.getRawQuery() == null;
    }

    @AssertTrue(message = "must be an absolute HTTP or HTTPS URI with a path and without user info, query, or fragment")
    boolean isJwkSetUriValid() {
        return isAbsoluteHttpUri(jwkSetUri)
                && jwkSetUri.getRawPath() != null
                && !jwkSetUri.getRawPath().isBlank()
                && jwkSetUri.getRawQuery() == null;
    }

    @AssertTrue(message = "must be between 1 millisecond and 10 seconds")
    boolean isJwksConnectTimeoutValid() {
        return isBoundedTimeout(jwksConnectTimeout);
    }

    @AssertTrue(message = "must be between 1 millisecond and 10 seconds")
    boolean isJwksReadTimeoutValid() {
        return isBoundedTimeout(jwksReadTimeout);
    }

    private static boolean isAbsoluteHttpUri(URI uri) {
        if (uri == null
                || !uri.isAbsolute()
                || uri.getHost() == null
                || uri.getUserInfo() != null
                || uri.getFragment() != null) {
            return false;
        }

        return "http".equalsIgnoreCase(uri.getScheme())
                || "https".equalsIgnoreCase(uri.getScheme());
    }

    private static boolean isBoundedTimeout(Duration timeout) {
        return timeout != null
                && timeout.compareTo(MIN_HTTP_TIMEOUT) >= 0
                && timeout.compareTo(MAX_HTTP_TIMEOUT) <= 0;
    }
}
