package io.github.yousseflah.oauth.authorization;

import io.github.yousseflah.oauth.authorization.jwk.EphemeralRsaKeyProvider;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.jwt.JwtEncoder;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
class AuthorizationServerApplicationTests {

    private final EphemeralRsaKeyProvider keyProvider;
    private final JwtEncoder jwtEncoder;

    @Autowired
    AuthorizationServerApplicationTests(EphemeralRsaKeyProvider keyProvider, JwtEncoder jwtEncoder) {
        this.keyProvider = keyProvider;
        this.jwtEncoder = jwtEncoder;
    }

    @Test
    void exposesEncoderBackedByTheSingleSigningKey() {
        assertThat(jwtEncoder).isSameAs(keyProvider.jwtEncoder());
    }
}
