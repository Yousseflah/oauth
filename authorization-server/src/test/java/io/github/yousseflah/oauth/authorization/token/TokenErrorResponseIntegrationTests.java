package io.github.yousseflah.oauth.authorization.token;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

import com.jayway.jsonpath.JsonPath;
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
class TokenErrorResponseIntegrationTests {

    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(5);

    private final HttpClient httpClient;
    private final URI tokenEndpoint;

    @Autowired
    TokenErrorResponseIntegrationTests(@LocalServerPort int serverPort) {
        httpClient = HttpClient.newBuilder()
                .connectTimeout(REQUEST_TIMEOUT)
                .build();
        tokenEndpoint = URI.create("http://localhost:" + serverPort + "/api/v1/tokens");
    }

    @AfterAll
    void closeHttpClient() {
        httpClient.close();
    }

    @Test
    void returnsBadRequestForMissingSubjectThroughTheRealServer() throws IOException, InterruptedException {
        var response = sendForm("");

        assertProblemDetail(response, "subject is required");
    }

    @Test
    void returnsSanitizedBadRequestForInvalidSubjectThroughTheRealServer()
            throws IOException, InterruptedException {
        var response = sendForm("subject=alice+smith");

        assertProblemDetail(
                response,
                "subject must contain 1 to 100 letters, digits, '.', '_', '@', or '-'");
        assertThat(response.body())
                .doesNotContain("alice smith", "InvalidSubjectException", "stackTrace", "trace");
    }

    @Test
    void rejectsSubjectInQueryStringThroughTheRealServer() throws IOException, InterruptedException {
        var queryEndpoint = URI.create(tokenEndpoint + "?subject=alice");
        var response = sendForm(queryEndpoint, "");

        assertProblemDetail(
                response,
                "query parameters are not allowed; submit subject in the form body");
    }

    @Test
    void documentsSecurityErrorShapeThroughTheRealServer() throws IOException, InterruptedException {
        var request = HttpRequest.newBuilder(tokenEndpoint)
                .timeout(REQUEST_TIMEOUT)
                .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                .GET()
                .build();
        var response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        assertBootError(response, 403, "Forbidden");
    }

    private HttpResponse<String> sendForm(String body) throws IOException, InterruptedException {
        return sendForm(tokenEndpoint, body);
    }

    private HttpResponse<String> sendForm(URI endpoint, String body) throws IOException, InterruptedException {
        var request = HttpRequest.newBuilder(endpoint)
                .timeout(REQUEST_TIMEOUT)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        return httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private static void assertProblemDetail(HttpResponse<String> response, String expectedDetail) {
        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.headers().firstValue(HttpHeaders.CONTENT_TYPE).orElseThrow())
                .startsWith(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
        assertThat(JsonPath.<String>read(response.body(), "$.title")).isEqualTo("Invalid token request");
        assertThat(JsonPath.<Integer>read(response.body(), "$.status")).isEqualTo(400);
        assertThat(JsonPath.<String>read(response.body(), "$.detail")).isEqualTo(expectedDetail);
    }

    private static void assertBootError(HttpResponse<String> response, int status, String error) {
        assertThat(response.statusCode()).isEqualTo(status);
        assertThat(response.headers().firstValue(HttpHeaders.CONTENT_TYPE).orElseThrow())
                .startsWith(MediaType.APPLICATION_JSON_VALUE);
        assertThat(JsonPath.<Integer>read(response.body(), "$.status")).isEqualTo(status);
        assertThat(JsonPath.<String>read(response.body(), "$.error")).isEqualTo(error);
        assertThat(response.body()).doesNotContain("exception", "stackTrace", "trace");
    }
}
