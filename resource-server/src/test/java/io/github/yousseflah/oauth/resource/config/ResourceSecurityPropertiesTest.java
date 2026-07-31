package io.github.yousseflah.oauth.resource.config;

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
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ResourceSecurityPropertiesTest {

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
        assertThat(validator.validate(validProperties())).isEmpty();
    }

    @ParameterizedTest
    @MethodSource("validTimeoutBoundaries")
    void acceptsTimeoutBoundaries(Duration timeout) {
        var properties = new ResourceSecurityProperties(
                URI.create("http://localhost:9000"),
                URI.create("http://localhost:9000/oauth2/jwks"),
                "mini-resource-server",
                "oauth-mini+jwt",
                timeout,
                timeout);

        assertThat(validator.validate(properties)).isEmpty();
    }

    @ParameterizedTest
    @MethodSource("invalidProperties")
    void rejectsInvalidSecurityProperties(ResourceSecurityProperties properties, String expectedPropertyPath) {
        assertThat(validator.validate(properties))
                .extracting(violation -> violation.getPropertyPath().toString())
                .contains(expectedPropertyPath);
    }

    private static Stream<Duration> validTimeoutBoundaries() {
        return Stream.of(Duration.ofMillis(1), Duration.ofSeconds(10));
    }

    private static Stream<Arguments> invalidProperties() {
        return Stream.of(
                invalid(
                        URI.create("/relative-issuer"),
                        URI.create("http://localhost:9000/oauth2/jwks"),
                        "mini-resource-server",
                        "oauth-mini+jwt",
                        Duration.ofSeconds(2),
                        Duration.ofSeconds(2),
                        "issuerValid"),
                invalid(
                        URI.create("http://localhost:9000/"),
                        URI.create("http://localhost:9000/oauth2/jwks"),
                        "mini-resource-server",
                        "oauth-mini+jwt",
                        Duration.ofSeconds(2),
                        Duration.ofSeconds(2),
                        "issuerValid"),
                invalid(
                        URI.create("http://localhost:9000"),
                        URI.create("http://localhost:9000"),
                        "mini-resource-server",
                        "oauth-mini+jwt",
                        Duration.ofSeconds(2),
                        Duration.ofSeconds(2),
                        "jwkSetUriValid"),
                invalid(
                        URI.create("http://localhost:9000"),
                        URI.create("http://localhost:9000/oauth2/jwks?source=untrusted"),
                        "mini-resource-server",
                        "oauth-mini+jwt",
                        Duration.ofSeconds(2),
                        Duration.ofSeconds(2),
                        "jwkSetUriValid"),
                invalid(
                        URI.create("http://localhost:9000"),
                        URI.create("http://localhost:9000/oauth2/jwks"),
                        " ",
                        "oauth-mini+jwt",
                        Duration.ofSeconds(2),
                        Duration.ofSeconds(2),
                        "audience"),
                invalid(
                        URI.create("http://localhost:9000"),
                        URI.create("http://localhost:9000/oauth2/jwks"),
                        "mini-resource-server",
                        "JWT",
                        Duration.ofSeconds(2),
                        Duration.ofSeconds(2),
                        "tokenType"),
                invalid(
                        URI.create("http://localhost:9000"),
                        URI.create("http://localhost:9000/oauth2/jwks"),
                        "mini-resource-server",
                        "oauth-mini+jwt",
                        Duration.ZERO,
                        Duration.ofSeconds(2),
                        "jwksConnectTimeoutValid"),
                invalid(
                        URI.create("http://localhost:9000"),
                        URI.create("http://localhost:9000/oauth2/jwks"),
                        "mini-resource-server",
                        "oauth-mini+jwt",
                        Duration.ofSeconds(11),
                        Duration.ofSeconds(2),
                        "jwksConnectTimeoutValid"),
                invalid(
                        URI.create("http://localhost:9000"),
                        URI.create("http://localhost:9000/oauth2/jwks"),
                        "mini-resource-server",
                        "oauth-mini+jwt",
                        Duration.ofSeconds(2),
                        Duration.ZERO,
                        "jwksReadTimeoutValid"),
                invalid(
                        URI.create("http://localhost:9000"),
                        URI.create("http://localhost:9000/oauth2/jwks"),
                        "mini-resource-server",
                        "oauth-mini+jwt",
                        Duration.ofSeconds(2),
                        Duration.ofSeconds(11),
                        "jwksReadTimeoutValid"));
    }

    private static Arguments invalid(
            URI issuer,
            URI jwkSetUri,
            String audience,
            String tokenType,
            Duration connectTimeout,
            Duration readTimeout,
            String expectedPropertyPath) {
        return Arguments.of(
                new ResourceSecurityProperties(
                        issuer,
                        jwkSetUri,
                        audience,
                        tokenType,
                        connectTimeout,
                        readTimeout),
                expectedPropertyPath);
    }

    private static ResourceSecurityProperties validProperties() {
        return new ResourceSecurityProperties(
                URI.create("http://localhost:9000"),
                URI.create("http://localhost:9000/oauth2/jwks"),
                "mini-resource-server",
                "oauth-mini+jwt",
                Duration.ofSeconds(2),
                Duration.ofSeconds(2));
    }
}
