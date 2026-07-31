package io.github.yousseflah.oauth.authorization.config;

import java.net.URI;
import java.time.Duration;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties("application.security")
public record AuthorizationProperties(
        @NotNull URI issuer,
        @NotBlank @Size(max = 100) @Pattern(regexp = "\\S+") String audience,
        @NotBlank @Pattern(regexp = "oauth-mini\\+jwt") String tokenType,
        @NotNull Duration accessTokenTtl) {

    @AssertTrue(message = "must be an absolute HTTP or HTTPS URI without user info, query, or fragment")
    public boolean isIssuerValid() {
        if (issuer == null
                || !issuer.isAbsolute()
                || issuer.getHost() == null
                || issuer.getUserInfo() != null
                || issuer.getQuery() != null
                || issuer.getFragment() != null) {
            return false;
        }

        return "http".equalsIgnoreCase(issuer.getScheme())
                || "https".equalsIgnoreCase(issuer.getScheme());
    }

    @AssertTrue(message = "must be greater than zero")
    public boolean isAccessTokenTtlValid() {
        return accessTokenTtl != null
                && !accessTokenTtl.isZero()
                && !accessTokenTtl.isNegative();
    }
}
