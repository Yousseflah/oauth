package io.github.yousseflah.oauth.authorization.config;

import org.junit.jupiter.api.Test;

import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

class AuthorizationSecurityPropertiesBindingTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withUserConfiguration(JwtConfiguration.class)
            .withPropertyValues(
                    "application.security.issuer=/relative-issuer",
                    "application.security.audience=mini-resource-server",
                    "application.security.token-type=oauth-mini+jwt",
                    "application.security.access-token-ttl=5m");

    @Test
    void failsApplicationStartupWhenSecurityPropertiesAreInvalid() {
        contextRunner.run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure())
                    .hasMessageContaining("application.security")
                    .rootCause()
                    .hasMessageContaining(
                            "must be an absolute HTTP or HTTPS origin URI without user info, path, query, or fragment");
        });
    }

}
