package io.github.yousseflah.oauth.authorization.config;

import io.github.yousseflah.oauth.authorization.jwk.EphemeralRsaKeyProvider;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtEncoder;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(AuthorizationProperties.class)
public class JwtConfiguration {

    @Bean
    EphemeralRsaKeyProvider ephemeralRsaKeyProvider() {
        return new EphemeralRsaKeyProvider();
    }

    @Bean
    JwtEncoder jwtEncoder(EphemeralRsaKeyProvider keyProvider) {
        return keyProvider.jwtEncoder();
    }
}
