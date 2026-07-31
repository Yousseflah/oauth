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

    private static final String ISSUER_URL = "http://localhost:9000";
    private static final String JWK_SET_URL = ISSUER_URL + "/oauth2/jwks";
    private static final URI ISSUER = URI.create(ISSUER_URL);
    private static final URI JWK_SET_URI = URI.create(JWK_SET_URL);

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

    @Test
    void acceptsHttpsIssuerAndJwkSetUri() {
        var properties = new ResourceSecurityProperties(
                URI.create("https://issuer.example"),
                URI.create("https://issuer.example/oauth2/jwks"),
                "mini-resource-server",
                "oauth-mini+jwt",
                Duration.ofSeconds(2),
                Duration.ofSeconds(2));

        assertThat(validator.validate(properties)).isEmpty();
    }

    @ParameterizedTest
    @MethodSource("validTimeoutBoundaries")
    void acceptsTimeoutBoundaries(Duration timeout) {
        var properties = new ResourceSecurityProperties(
                ISSUER,
                JWK_SET_URI,
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
                        JWK_SET_URI,
                        "mini-resource-server",
                        "oauth-mini+jwt",
                        Duration.ofSeconds(2),
                        Duration.ofSeconds(2),
                        "issuerValid"),
                invalid(
                        URI.create(ISSUER_URL + "/"),
                        JWK_SET_URI,
                        "mini-resource-server",
                        "oauth-mini+jwt",
                        Duration.ofSeconds(2),
                        Duration.ofSeconds(2),
                        "issuerValid"),
                invalid(
                        URI.create(ISSUER_URL + "?untrusted=value"),
                        JWK_SET_URI,
                        "mini-resource-server",
                        "oauth-mini+jwt",
                        Duration.ofSeconds(2),
                        Duration.ofSeconds(2),
                        "issuerValid"),
                invalid(
                        URI.create("http://operator:secret@localhost:9000"),
                        JWK_SET_URI,
                        "mini-resource-server",
                        "oauth-mini+jwt",
                        Duration.ofSeconds(2),
                        Duration.ofSeconds(2),
                        "issuerValid"),
                invalid(
                        URI.create(ISSUER_URL + "#fragment"),
                        JWK_SET_URI,
                        "mini-resource-server",
                        "oauth-mini+jwt",
                        Duration.ofSeconds(2),
                        Duration.ofSeconds(2),
                        "issuerValid"),
                invalid(
                        URI.create("ftp://localhost:9000"),
                        JWK_SET_URI,
                        "mini-resource-server",
                        "oauth-mini+jwt",
                        Duration.ofSeconds(2),
                        Duration.ofSeconds(2),
                        "issuerValid"),
                invalid(
                        URI.create("mailto:issuer@example.com"),
                        JWK_SET_URI,
                        "mini-resource-server",
                        "oauth-mini+jwt",
                        Duration.ofSeconds(2),
                        Duration.ofSeconds(2),
                        "issuerValid"),
                invalid(
                        null,
                        JWK_SET_URI,
                        "mini-resource-server",
                        "oauth-mini+jwt",
                        Duration.ofSeconds(2),
                        Duration.ofSeconds(2),
                        "issuerValid"),
                invalid(
                        ISSUER,
                        ISSUER,
                        "mini-resource-server",
                        "oauth-mini+jwt",
                        Duration.ofSeconds(2),
                        Duration.ofSeconds(2),
                        "jwkSetUriValid"),
                invalid(
                        ISSUER,
                        URI.create("/oauth2/jwks"),
                        "mini-resource-server",
                        "oauth-mini+jwt",
                        Duration.ofSeconds(2),
                        Duration.ofSeconds(2),
                        "jwkSetUriValid"),
                invalid(
                        ISSUER,
                        URI.create("ftp://localhost:9000/oauth2/jwks"),
                        "mini-resource-server",
                        "oauth-mini+jwt",
                        Duration.ofSeconds(2),
                        Duration.ofSeconds(2),
                        "jwkSetUriValid"),
                invalid(
                        ISSUER,
                        URI.create(JWK_SET_URL + "#fragment"),
                        "mini-resource-server",
                        "oauth-mini+jwt",
                        Duration.ofSeconds(2),
                        Duration.ofSeconds(2),
                        "jwkSetUriValid"),
                invalid(
                        ISSUER,
                        null,
                        "mini-resource-server",
                        "oauth-mini+jwt",
                        Duration.ofSeconds(2),
                        Duration.ofSeconds(2),
                        "jwkSetUriValid"),
                invalid(
                        ISSUER,
                        JWK_SET_URI,
                        "mini-resource-server",
                        "oauth-mini+jwt",
                        null,
                        Duration.ofSeconds(2),
                        "jwksConnectTimeoutValid"),
                invalid(
                        ISSUER,
                        JWK_SET_URI,
                        "mini-resource-server",
                        "oauth-mini+jwt",
                        Duration.ofSeconds(2),
                        null,
                        "jwksReadTimeoutValid"),
                invalid(
                        ISSUER,
                        URI.create(JWK_SET_URL + "?source=untrusted"),
                        "mini-resource-server",
                        "oauth-mini+jwt",
                        Duration.ofSeconds(2),
                        Duration.ofSeconds(2),
                        "jwkSetUriValid"),
                invalid(
                        ISSUER,
                        JWK_SET_URI,
                        " ",
                        "oauth-mini+jwt",
                        Duration.ofSeconds(2),
                        Duration.ofSeconds(2),
                        "audience"),
                invalid(
                        ISSUER,
                        JWK_SET_URI,
                        "mini-resource-server",
                        "JWT",
                        Duration.ofSeconds(2),
                        Duration.ofSeconds(2),
                        "tokenType"),
                invalid(
                        ISSUER,
                        JWK_SET_URI,
                        "mini-resource-server",
                        "oauth-mini+jwt",
                        Duration.ZERO,
                        Duration.ofSeconds(2),
                        "jwksConnectTimeoutValid"),
                invalid(
                        ISSUER,
                        JWK_SET_URI,
                        "mini-resource-server",
                        "oauth-mini+jwt",
                        Duration.ofSeconds(11),
                        Duration.ofSeconds(2),
                        "jwksConnectTimeoutValid"),
                invalid(
                        ISSUER,
                        JWK_SET_URI,
                        "mini-resource-server",
                        "oauth-mini+jwt",
                        Duration.ofSeconds(2),
                        Duration.ZERO,
                        "jwksReadTimeoutValid"),
                invalid(
                        ISSUER,
                        JWK_SET_URI,
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
                ISSUER,
                JWK_SET_URI,
                "mini-resource-server",
                "oauth-mini+jwt",
                Duration.ofSeconds(2),
                Duration.ofSeconds(2));
    }
}
