package io.github.yousseflah.oauth.authorization.jwk;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

@SpringBootTest(webEnvironment = RANDOM_PORT)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class JwkSetErrorDispatchIntegrationTests {

    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(5);

    private final HttpClient httpClient;
    private final URI serverUri;

    @Autowired
    JwkSetErrorDispatchIntegrationTests(@LocalServerPort int serverPort) {
        httpClient = HttpClient.newBuilder()
                .connectTimeout(REQUEST_TIMEOUT)
                .build();
        serverUri = URI.create("http://localhost:" + serverPort);
    }

    @AfterAll
    void closeHttpClient() {
        httpClient.close();
    }

    @Test
    void preservesNotAcceptableStatusThroughErrorDispatch() throws IOException, InterruptedException {
        var request = requestFor("/oauth2/jwks")
                .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                .build();

        var response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        assertThat(response.statusCode()).isEqualTo(406);
    }

    @Test
    void deniesDirectRequestsToErrorEndpoint() throws IOException, InterruptedException {
        var request = requestFor("/error").build();

        var response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        assertThat(response.statusCode()).isEqualTo(403);
    }

    private HttpRequest.Builder requestFor(String path) {
        return HttpRequest.newBuilder(serverUri.resolve(path))
                .timeout(REQUEST_TIMEOUT)
                .GET();
    }
}
