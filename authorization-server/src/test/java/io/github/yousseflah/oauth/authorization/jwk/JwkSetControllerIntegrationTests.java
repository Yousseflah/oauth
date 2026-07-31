package io.github.yousseflah.oauth.authorization.jwk;

import java.util.List;

import com.nimbusds.jose.jwk.JWKSet;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.head;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class JwkSetControllerIntegrationTests {

    private static final List<String> PRIVATE_RSA_PARAMETERS =
            List.of("d", "p", "q", "dp", "dq", "qi", "oth");
    private static final MediaType JWK_SET_MEDIA_TYPE = MediaType.parseMediaType(JWKSet.MIME_TYPE);

    private final WebApplicationContext applicationContext;
    private final EphemeralRsaKeyProvider keyProvider;

    private MockMvc mockMvc;

    @Autowired
    JwkSetControllerIntegrationTests(
            WebApplicationContext applicationContext,
            EphemeralRsaKeyProvider keyProvider) {
        this.applicationContext = applicationContext;
        this.keyProvider = keyProvider;
    }

    @BeforeAll
    void configureMockMvc() {
        mockMvc = MockMvcBuilders.webAppContextSetup(applicationContext)
                .apply(springSecurity())
                .build();
    }

    @Test
    void publishesCurrentPublicSigningKey() throws Exception {
        var publicJwk = keyProvider.publicJwk();

        mockMvc.perform(get("/oauth2/jwks").accept(JWK_SET_MEDIA_TYPE))
                .andExpect(status().isOk())
                .andExpect(content().contentType(JWK_SET_MEDIA_TYPE))
                .andExpect(jsonPath("$.keys.length()").value(1))
                .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
                .andExpect(jsonPath("$.keys[0].use").value("sig"))
                .andExpect(jsonPath("$.keys[0].alg").value("RS256"))
                .andExpect(jsonPath("$.keys[0].kid").value(publicJwk.getKeyID()))
                .andExpect(jsonPath("$.keys[0].n").value(publicJwk.getModulus().toString()))
                .andExpect(jsonPath("$.keys[0].e").value(publicJwk.getPublicExponent().toString()));
    }

    @Test
    void neverPublishesPrivateRsaParameters() throws Exception {
        var resultActions = mockMvc.perform(get("/oauth2/jwks"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys.length()").value(1));

        for (var privateParameter : PRIVATE_RSA_PARAMETERS) {
            resultActions.andExpect(jsonPath("$.keys[0]." + privateParameter).doesNotExist());
        }
    }

    @Test
    void permitsOnlyTheExactJwksGetRequest() throws Exception {
        mockMvc.perform(post("/oauth2/jwks"))
                .andExpect(status().isForbidden());
        mockMvc.perform(head("/oauth2/jwks"))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/oauth2/jwks/"))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/login"))
                .andExpect(status().isForbidden());
        mockMvc.perform(post("/logout"))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/unmapped"))
                .andExpect(status().isForbidden());
    }

    @Test
    void doesNotCreateAnHttpSessionForPublicJwksRequests() throws Exception {
        var result = mockMvc.perform(get("/oauth2/jwks"))
                .andExpect(status().isOk())
                .andExpect(header().doesNotExist("Set-Cookie"))
                .andReturn();

        assertThat(result.getRequest().getSession(false)).isNull();
    }
}
