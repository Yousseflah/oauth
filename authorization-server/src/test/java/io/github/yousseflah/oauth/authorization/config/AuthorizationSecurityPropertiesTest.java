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
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class AuthorizationSecurityPropertiesTest {

    private static final String ISSUER_URL = "http://localhost:9000";
    private static final URI ISSUER = URI.create(ISSUER_URL);

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

    @Test
    void acceptsMaximumAccessTokenTtl() {
        var properties = new AuthorizationSecurityProperties(
                ISSUER,
                "mini-resource-server",
                "oauth-mini+jwt",
                Duration.ofMinutes(15));

        assertThat(validator.validate(properties)).isEmpty();
    }

    @Test
    void acceptsMinimumAccessTokenTtl() {
        var properties = new AuthorizationSecurityProperties(
                ISSUER,
                "mini-resource-server",
                "oauth-mini+jwt",
                Duration.ofSeconds(1));

        assertThat(validator.validate(properties)).isEmpty();
    }

    @Test
    void acceptsHttpsIssuer() {
        var properties = new AuthorizationSecurityProperties(
                URI.create("https://issuer.example"),
                "mini-resource-server",
                "oauth-mini+jwt",
                Duration.ofMinutes(5));

        assertThat(validator.validate(properties)).isEmpty();
    }

    @ParameterizedTest
    @MethodSource("invalidProperties")
    void rejectsInvalidSecurityProperties(
            AuthorizationSecurityProperties properties,
            String expectedPropertyPath) {
        assertThat(validator.validate(properties))
                .extracting(violation -> violation.getPropertyPath().toString())
                .contains(expectedPropertyPath);
    }

    private static Stream<Arguments> invalidProperties() {
        return Stream.of(
                Arguments.of(
                        new AuthorizationSecurityProperties(
                                URI.create("/relative-issuer"),
                                "mini-resource-server",
                                "oauth-mini+jwt",
                                Duration.ofMinutes(5)),
                        "issuerValid"),
                Arguments.of(
                        new AuthorizationSecurityProperties(
                                URI.create(ISSUER_URL + "?untrusted=value"),
                                "mini-resource-server",
                                "oauth-mini+jwt",
                                Duration.ofMinutes(5)),
                        "issuerValid"),
                Arguments.of(
                        new AuthorizationSecurityProperties(
                                URI.create(ISSUER_URL + "/"),
                                "mini-resource-server",
                                "oauth-mini+jwt",
                                Duration.ofMinutes(5)),
                        "issuerValid"),
                Arguments.of(
                        new AuthorizationSecurityProperties(
                                URI.create(ISSUER_URL + "/issuer"),
                                "mini-resource-server",
                                "oauth-mini+jwt",
                                Duration.ofMinutes(5)),
                        "issuerValid"),
                Arguments.of(
                        new AuthorizationSecurityProperties(
                                URI.create("http://operator:secret@localhost:9000"),
                                "mini-resource-server",
                                "oauth-mini+jwt",
                                Duration.ofMinutes(5)),
                        "issuerValid"),
                Arguments.of(
                        new AuthorizationSecurityProperties(
                                URI.create(ISSUER_URL + "#fragment"),
                                "mini-resource-server",
                                "oauth-mini+jwt",
                                Duration.ofMinutes(5)),
                        "issuerValid"),
                Arguments.of(
                        new AuthorizationSecurityProperties(
                                URI.create("ftp://localhost:9000"),
                                "mini-resource-server",
                                "oauth-mini+jwt",
                                Duration.ofMinutes(5)),
                        "issuerValid"),
                Arguments.of(
                        new AuthorizationSecurityProperties(
                                URI.create("mailto:issuer@example.com"),
                                "mini-resource-server",
                                "oauth-mini+jwt",
                                Duration.ofMinutes(5)),
                        "issuerValid"),
                Arguments.of(
                        new AuthorizationSecurityProperties(
                                null,
                                "mini-resource-server",
                                "oauth-mini+jwt",
                                Duration.ofMinutes(5)),
                        "issuerValid"),
                Arguments.of(
                        new AuthorizationSecurityProperties(
                                ISSUER,
                                "mini-resource-server",
                                "oauth-mini+jwt",
                                null),
                        "accessTokenTtlValid"),
                Arguments.of(
                        new AuthorizationSecurityProperties(
                                ISSUER,
                                " ",
                                "oauth-mini+jwt",
                                Duration.ofMinutes(5)),
                        "audience"),
                Arguments.of(
                        new AuthorizationSecurityProperties(
                                ISSUER,
                                "mini-resource-server",
                                "JWT",
                                Duration.ofMinutes(5)),
                        "tokenType"),
                Arguments.of(
                        new AuthorizationSecurityProperties(
                                ISSUER,
                                "mini-resource-server",
                                "oauth-mini+jwt",
                                Duration.ZERO),
                        "accessTokenTtlValid"),
                Arguments.of(
                        new AuthorizationSecurityProperties(
                                ISSUER,
                                "mini-resource-server",
                                "oauth-mini+jwt",
                                Duration.ofMillis(1500)),
                        "accessTokenTtlValid"),
                Arguments.of(
                        new AuthorizationSecurityProperties(
                                ISSUER,
                                "mini-resource-server",
                                "oauth-mini+jwt",
                                Duration.ofMinutes(16)),
                        "accessTokenTtlValid"));
    }

    private static AuthorizationSecurityProperties validProperties() {
        return new AuthorizationSecurityProperties(
                ISSUER,
                "mini-resource-server",
                "oauth-mini+jwt",
                Duration.ofMinutes(5));
    }
}
