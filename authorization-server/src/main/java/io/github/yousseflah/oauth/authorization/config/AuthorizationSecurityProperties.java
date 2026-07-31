package io.github.yousseflah.oauth.authorization.config;

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
public record AuthorizationSecurityProperties(
        @NotNull URI issuer,
        @NotNull @Size(max = 100) @Pattern(regexp = "\\S+") String audience,
        // Keep the type visible in configuration, but pin it to prevent issuer/consumer contract drift.
        @NotNull @Pattern(regexp = "oauth-mini\\+jwt") String tokenType,
        @NotNull Duration accessTokenTtl) {

    private static final Duration MIN_ACCESS_TOKEN_TTL = Duration.ofSeconds(1);
    private static final Duration MAX_ACCESS_TOKEN_TTL = Duration.ofMinutes(15);

    @AssertTrue(message = "must be an absolute HTTP or HTTPS origin URI without user info, path, query, or fragment")
    public boolean isIssuerValid() {
        return isAbsoluteHttpUri(issuer)
                && (issuer.getRawPath() == null || issuer.getRawPath().isEmpty())
                && issuer.getRawQuery() == null;
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

    @AssertTrue(message = "must be a whole number of seconds between 1 second and 15 minutes")
    public boolean isAccessTokenTtlValid() {
        return accessTokenTtl != null
                && accessTokenTtl.compareTo(MIN_ACCESS_TOKEN_TTL) >= 0
                && accessTokenTtl.getNano() == 0
                && accessTokenTtl.compareTo(MAX_ACCESS_TOKEN_TTL) <= 0;
    }
}
