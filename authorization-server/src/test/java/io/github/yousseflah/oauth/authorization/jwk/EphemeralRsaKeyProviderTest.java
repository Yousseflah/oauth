package io.github.yousseflah.oauth.authorization.jwk;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.KeyUse;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class EphemeralRsaKeyProviderTest {

    private EphemeralRsaKeyProvider keyProvider;

    @BeforeAll
    void generateKey() {
        keyProvider = new EphemeralRsaKeyProvider();
    }

    @Test
    void generatesRsa2048SigningKeyWithUuidKeyId() {
        var publicJwk = keyProvider.publicJwk();

        assertThat(publicJwk.size()).isEqualTo(2048);
        assertThat(publicJwk.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
        assertThat(publicJwk.getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        assertThat(publicJwk.getKeyID()).isNotBlank();
        assertThatCode(() -> UUID.fromString(publicJwk.getKeyID())).doesNotThrowAnyException();
    }

    @Test
    void exposesOnlyPublicRsaParameters() {
        var publicJwk = keyProvider.publicJwk();

        assertThat(publicJwk.isPrivate()).isFalse();
        assertThat(publicJwk.toJSONObject())
                .doesNotContainKeys(JwkTestConstants.RSA_PRIVATE_PARAMETERS.toArray(String[]::new));
    }

    @Test
    void cachesAnImmutablePublicJwkSetDocument() {
        var publicJwkSet = keyProvider.publicJwkSet();

        assertThat(keyProvider.publicJwkSet()).isSameAs(publicJwkSet);
        assertThatThrownBy(publicJwkSet::clear).isInstanceOf(UnsupportedOperationException.class);

        var keys = (List<?>) publicJwkSet.get("keys");
        assertThatThrownBy(keys::clear).isInstanceOf(UnsupportedOperationException.class);

        var publicKey = (Map<?, ?>) keys.getFirst();
        assertThatThrownBy(publicKey::clear).isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void encodesWithCurrentSigningKey() {
        var claims = JwtClaimsSet.builder().subject("test-subject").build();
        var jwt = keyProvider.jwtEncoder().encode(JwtEncoderParameters.from(claims));

        assertThat(jwt.getHeaders()).containsEntry("kid", keyProvider.publicJwk().getKeyID());
    }

    @Test
    void assignsDifferentKeyIdsToDifferentProviders() {
        var anotherKeyProvider = new EphemeralRsaKeyProvider();

        assertThat(anotherKeyProvider.publicJwk().getKeyID())
                .isNotEqualTo(keyProvider.publicJwk().getKeyID());
    }
}
