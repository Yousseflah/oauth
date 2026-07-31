package io.github.yousseflah.oauth.authorization.token;

import java.security.interfaces.RSAPublicKey;

import io.github.yousseflah.oauth.authorization.jwk.EphemeralRsaKeyProvider;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
class TokenServiceSignatureIntegrationTest {

    private final TokenService tokenService;
    private final EphemeralRsaKeyProvider keyProvider;

    @Autowired
    TokenServiceSignatureIntegrationTest(TokenService tokenService, EphemeralRsaKeyProvider keyProvider) {
        this.tokenService = tokenService;
        this.keyProvider = keyProvider;
    }

    @Test
    void signsTokenVerifiableByTheCurrentPublicKey() throws Exception {
        var issuedToken = tokenService.issueToken("alice");
        var publicKey = (RSAPublicKey) keyProvider.publicJwk().toRSAPublicKey();
        var decoder = NimbusJwtDecoder.withPublicKey(publicKey)
                .signatureAlgorithm(SignatureAlgorithm.RS256)
                .validateType(false)
                .build();
        decoder.setJwtValidator(new JwtTimestampValidator());

        var decodedToken = decoder.decode(issuedToken.accessToken());

        assertThat(decodedToken.getSubject()).isEqualTo("alice");
        assertThat(decodedToken.getHeaders())
                .containsEntry("alg", "RS256")
                .containsEntry("typ", "oauth-mini+jwt")
                .containsEntry("kid", keyProvider.publicJwk().getKeyID());
    }
}
