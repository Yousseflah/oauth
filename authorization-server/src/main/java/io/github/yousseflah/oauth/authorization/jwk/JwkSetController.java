package io.github.yousseflah.oauth.authorization.jwk;

import java.util.Map;

import com.nimbusds.jose.jwk.JWKSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/oauth2")
public class JwkSetController {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwkSetController.class);

    private final EphemeralRsaKeyProvider keyProvider;

    public JwkSetController(EphemeralRsaKeyProvider keyProvider) {
        this.keyProvider = keyProvider;
    }

    @GetMapping(value = "/jwks", produces = JWKSet.MIME_TYPE)
    public Map<String, Object> getJwkSet() {
        var publicJwk = keyProvider.publicJwk();
        LOGGER.debug("Publishing public JWKS with kid={}", publicJwk.getKeyID());
        return new JWKSet(publicJwk).toJSONObject();
    }
}
