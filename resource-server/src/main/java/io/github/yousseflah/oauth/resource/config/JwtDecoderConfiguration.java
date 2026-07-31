package io.github.yousseflah.oauth.resource.config;

import java.net.http.HttpClient;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.JwtTypeValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.web.client.RestTemplate;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(ResourceSecurityProperties.class)
class JwtDecoderConfiguration {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtDecoderConfiguration.class);

    @Bean(destroyMethod = "close")
    HttpClient jwksHttpClient(ResourceSecurityProperties properties) {
        return HttpClient.newBuilder()
                .connectTimeout(properties.jwksConnectTimeout())
                // Do not let a trusted JWKS endpoint redirect key retrieval to an untrusted host.
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    @Bean
    JwtDecoder jwtDecoder(ResourceSecurityProperties properties, HttpClient jwksHttpClient) {
        var requestFactory = new JdkClientHttpRequestFactory(jwksHttpClient);
        requestFactory.setReadTimeout(properties.jwksReadTimeout());
        var jwksRestOperations = new RestTemplate(requestFactory);

        var decoder = NimbusJwtDecoder.withJwkSetUri(properties.jwkSetUri().toString())
                .jwsAlgorithm(SignatureAlgorithm.RS256)
                .validateType(false)
                .restOperations(jwksRestOperations)
                .build();

        var timestampValidator = new JwtTimestampValidator();
        timestampValidator.setAllowEmptyExpiryClaim(false);
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                timestampValidator,
                new JwtIssuerValidator(properties.issuer().toString()),
                new AudienceValidator(properties.audience()),
                new JwtTypeValidator(properties.tokenType())));

        LOGGER.info(
                "Configured JWT validation with algorithm=RS256, issuer={}, audience={}",
                properties.issuer(),
                properties.audience());
        return decoder;
    }
}
