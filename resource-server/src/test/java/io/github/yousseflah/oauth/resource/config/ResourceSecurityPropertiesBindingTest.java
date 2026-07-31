package io.github.yousseflah.oauth.resource.config;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

class ResourceSecurityPropertiesBindingTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withUserConfiguration(JwtDecoderConfiguration.class)
            .withPropertyValues(
                    "application.security.issuer=/relative-issuer",
                    "application.security.jwk-set-uri=http://localhost:9000/oauth2/jwks",
                    "application.security.audience=mini-resource-server",
                    "application.security.token-type=oauth-mini+jwt",
                    "application.security.jwks-connect-timeout=2s",
                    "application.security.jwks-read-timeout=2s");

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
