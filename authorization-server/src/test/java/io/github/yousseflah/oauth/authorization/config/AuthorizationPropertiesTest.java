package io.github.yousseflah.oauth.authorization.config;

import java.net.URI;
import java.time.Duration;
import java.util.stream.Stream;

import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class AuthorizationPropertiesTest {

    private ValidatorFactory validatorFactory;
    private Validator validator;

    @BeforeAll
    void setUpValidator() {
        validatorFactory = Validation.buildDefaultValidatorFactory();
        validator = validatorFactory.getValidator();
    }

    @AfterAll
    void closeValidatorFactory() {
        validatorFactory.close();
    }

    @Test
    void acceptsValidSecurityProperties() {
        var properties = validProperties();

        assertThat(validator.validate(properties)).isEmpty();
    }

    @ParameterizedTest
    @MethodSource("invalidProperties")
    void rejectsInvalidSecurityProperties(AuthorizationProperties properties) {
        assertThat(validator.validate(properties)).isNotEmpty();
    }

    private static Stream<AuthorizationProperties> invalidProperties() {
        return Stream.of(
                new AuthorizationProperties(
                        URI.create("/relative-issuer"),
                        "mini-resource-server",
                        "oauth-mini+jwt",
                        Duration.ofMinutes(5)),
                new AuthorizationProperties(
                        URI.create("http://localhost:9000?untrusted=value"),
                        "mini-resource-server",
                        "oauth-mini+jwt",
                        Duration.ofMinutes(5)),
                new AuthorizationProperties(
                        URI.create("http://localhost:9000"),
                        " ",
                        "oauth-mini+jwt",
                        Duration.ofMinutes(5)),
                new AuthorizationProperties(
                        URI.create("http://localhost:9000"),
                        "mini-resource-server",
                        "JWT",
                        Duration.ofMinutes(5)),
                new AuthorizationProperties(
                        URI.create("http://localhost:9000"),
                        "mini-resource-server",
                        "oauth-mini+jwt",
                        Duration.ZERO));
    }

    private static AuthorizationProperties validProperties() {
        return new AuthorizationProperties(
                URI.create("http://localhost:9000"),
                "mini-resource-server",
                "oauth-mini+jwt",
                Duration.ofMinutes(5));
    }
}
