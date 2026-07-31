package io.github.yousseflah.oauth.authorization.token;

import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Stream;

import com.jayway.jsonpath.JsonPath;
import io.github.yousseflah.oauth.authorization.jwk.EphemeralRsaKeyProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.head;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class TokenControllerIntegrationTests {

    private static final MediaType PROBLEM_DETAIL_MEDIA_TYPE = MediaType.APPLICATION_PROBLEM_JSON;

    private final WebApplicationContext applicationContext;
    private final EphemeralRsaKeyProvider keyProvider;

    private MockMvc mockMvc;

    @Autowired
    TokenControllerIntegrationTests(
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
    void issuesSignedTokenWithDocumentedResponse() throws Exception {
        var result = mockMvc.perform(post("/api/v1/tokens")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .accept(MediaType.APPLICATION_JSON)
                        .param("subject", "  alice@example.com  "))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(header().string(HttpHeaders.CACHE_CONTROL, containsString("no-store")))
                .andExpect(header().string(HttpHeaders.PRAGMA, "no-cache"))
                .andExpect(header().doesNotExist(HttpHeaders.SET_COOKIE))
                .andExpect(jsonPath("$.access_token").isNotEmpty())
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.expires_in").value(300))
                .andReturn();

        assertThat(result.getRequest().getSession(false)).isNull();
        var responseBody = result.getResponse().getContentAsString();
        var responseFields = JsonPath.<Map<String, Object>>read(responseBody, "$");
        assertThat(responseFields).containsOnlyKeys("access_token", "token_type", "expires_in");

        var accessToken = JsonPath.<String>read(responseBody, "$.access_token");
        var decodedToken = decode(accessToken);
        assertThat(decodedToken.getHeaders())
                .containsEntry("alg", "RS256")
                .containsEntry("typ", "oauth-mini+jwt")
                .containsEntry("kid", keyProvider.publicJwk().getKeyID());
        assertThat(decodedToken.getIssuer().toString()).isEqualTo("http://localhost:9000");
        assertThat(decodedToken.getSubject()).isEqualTo("alice@example.com");
        assertThat(decodedToken.getAudience()).containsExactly("mini-resource-server");
        assertThat(decodedToken.getIssuedAt()).isNotNull();
        assertThat(decodedToken.getExpiresAt()).isNotNull();
        assertThat(Duration.between(decodedToken.getIssuedAt(), decodedToken.getExpiresAt()))
                .isEqualTo(Duration.ofMinutes(5));
        assertThatCode(() -> UUID.fromString(decodedToken.getId())).doesNotThrowAnyException();
    }

    @Test
    void returnsProblemDetailWhenSubjectIsMissing() throws Exception {
        mockMvc.perform(post("/api/v1/tokens")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(PROBLEM_DETAIL_MEDIA_TYPE))
                .andExpect(jsonPath("$.title").value("Invalid token request"))
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.detail").value("subject is required"))
                .andExpect(jsonPath("$.exception").doesNotExist())
                .andExpect(jsonPath("$.trace").doesNotExist());
    }

    @Test
    void rejectsSubjectInTheQueryString() throws Exception {
        mockMvc.perform(post("/api/v1/tokens")
                        .queryParam("subject", "alice")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(PROBLEM_DETAIL_MEDIA_TYPE))
                .andExpect(jsonPath("$.title").value("Invalid token request"))
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.detail").value(
                        "query parameters are not allowed; submit subject in the form body"));
    }

    @ParameterizedTest
    @MethodSource("invalidSubjects")
    void returnsProblemDetailForInvalidSubject(String subject) throws Exception {
        mockMvc.perform(post("/api/v1/tokens")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .accept(MediaType.APPLICATION_JSON)
                        .param("subject", subject))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentTypeCompatibleWith(PROBLEM_DETAIL_MEDIA_TYPE))
                .andExpect(jsonPath("$.title").value("Invalid token request"))
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.detail").value(
                        "subject must contain 1 to 100 letters, digits, '.', '_', '@', or '-'"))
                .andExpect(jsonPath("$.exception").doesNotExist())
                .andExpect(jsonPath("$.trace").doesNotExist());
    }

    @Test
    void permitsOnlyTheExactFormEncodedPostRequest() throws Exception {
        mockMvc.perform(get("/api/v1/tokens"))
                .andExpect(status().isForbidden());
        mockMvc.perform(head("/api/v1/tokens"))
                .andExpect(status().isForbidden());
        mockMvc.perform(put("/api/v1/tokens"))
                .andExpect(status().isForbidden());
        mockMvc.perform(post("/api/v1/tokens/"))
                .andExpect(status().isForbidden());
        mockMvc.perform(post("/api/v1/token"))
                .andExpect(status().isForbidden());
        mockMvc.perform(post("/api/v1/tokens")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"subject\":\"alice\"}"))
                .andExpect(status().isUnsupportedMediaType())
                .andExpect(content().contentTypeCompatibleWith(PROBLEM_DETAIL_MEDIA_TYPE))
                .andExpect(jsonPath("$.title").value("Unsupported Media Type"))
                .andExpect(jsonPath("$.status").value(415));
        mockMvc.perform(post("/api/v1/tokens")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .accept(MediaType.APPLICATION_XML)
                        .param("subject", "alice"))
                .andExpect(status().isNotAcceptable())
                .andExpect(content().contentTypeCompatibleWith(PROBLEM_DETAIL_MEDIA_TYPE))
                .andExpect(jsonPath("$.title").value("Not Acceptable"))
                .andExpect(jsonPath("$.status").value(406));
    }

    private Jwt decode(String accessToken) throws Exception {
        var publicKey = (RSAPublicKey) keyProvider.publicJwk().toRSAPublicKey();
        var decoder = NimbusJwtDecoder.withPublicKey(publicKey)
                .signatureAlgorithm(SignatureAlgorithm.RS256)
                .validateType(false)
                .build();
        decoder.setJwtValidator(new JwtTimestampValidator());
        return decoder.decode(accessToken);
    }

    private static Stream<String> invalidSubjects() {
        return Stream.of(
                "",
                "   ",
                "a".repeat(101),
                "alice smith",
                "alice/bob");
    }
}
