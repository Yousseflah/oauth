package io.github.yousseflah.oauth.authorization;

import io.github.yousseflah.oauth.authorization.jwk.EphemeralRsaKeyProvider;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.tomcat.autoconfigure.TomcatServerProperties;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.util.unit.DataSize;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
class AuthorizationServerApplicationTests {

    private final EphemeralRsaKeyProvider keyProvider;
    private final JwtEncoder jwtEncoder;
    private final ListableBeanFactory beanFactory;
    private final TomcatServerProperties tomcatServerProperties;

    @Autowired
    AuthorizationServerApplicationTests(
            EphemeralRsaKeyProvider keyProvider,
            JwtEncoder jwtEncoder,
            ListableBeanFactory beanFactory,
            TomcatServerProperties tomcatServerProperties) {
        this.keyProvider = keyProvider;
        this.jwtEncoder = jwtEncoder;
        this.beanFactory = beanFactory;
        this.tomcatServerProperties = tomcatServerProperties;
    }

    @Test
    void exposesEncoderBackedByTheSingleSigningKey() {
        assertThat(jwtEncoder).isSameAs(keyProvider.jwtEncoder());
    }

    @Test
    void doesNotConfigureAnUnusedUserDetailsService() {
        assertThat(beanFactory.getBeanNamesForType(UserDetailsService.class)).isEmpty();
    }

    @Test
    void limitsFormPostsToSixteenKilobytes() {
        assertThat(tomcatServerProperties.getMaxHttpFormPostSize())
                .isEqualTo(DataSize.ofKilobytes(16));
    }
}
