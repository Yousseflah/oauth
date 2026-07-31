package io.github.yousseflah.oauth.authorization.jwk;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

public final class EphemeralRsaKeyProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(EphemeralRsaKeyProvider.class);
    private static final int RSA_KEY_SIZE = 2048;

    private final RSAKey privateJwk;
    private final RSAKey publicJwk;
    private final JwtEncoder jwtEncoder;

    public EphemeralRsaKeyProvider() {
        privateJwk = generatePrivateJwk();
        publicJwk = privateJwk.toPublicJWK();
        var jwkSource = new ImmutableJWKSet<SecurityContext>(new JWKSet(privateJwk));
        jwtEncoder = new NimbusJwtEncoder(jwkSource);

        LOGGER.info(
                "Initialized ephemeral RSA signing key with kid={} and size={} bits",
                publicJwk.getKeyID(),
                publicJwk.size());
    }

    public RSAKey publicJwk() {
        return publicJwk;
    }

    public JwtEncoder jwtEncoder() {
        return jwtEncoder;
    }

    private static RSAKey generatePrivateJwk() {
        try {
            var keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(RSA_KEY_SIZE);
            var keyPair = keyPairGenerator.generateKeyPair();
            var publicKey = (RSAPublicKey) keyPair.getPublic();
            var privateKey = (RSAPrivateKey) keyPair.getPrivate();

            return new RSAKey.Builder(publicKey)
                    .privateKey(privateKey)
                    .keyUse(KeyUse.SIGNATURE)
                    .algorithm(JWSAlgorithm.RS256)
                    .keyID(UUID.randomUUID().toString())
                    .build();
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("RSA key pair generation is unavailable", exception);
        }
    }
}
