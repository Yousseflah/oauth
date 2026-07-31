package io.github.yousseflah.oauth.resource;

import java.net.http.HttpClient;
import java.time.Duration;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
class ResourceServerApplicationTests {

    private final ListableBeanFactory beanFactory;
    private final HttpClient jwksHttpClient;

    @Autowired
    ResourceServerApplicationTests(ListableBeanFactory beanFactory, HttpClient jwksHttpClient) {
        this.beanFactory = beanFactory;
        this.jwksHttpClient = jwksHttpClient;
    }

    @Test
    void exposesOnlyTheCustomJwtDecoder() {
        assertThat(beanFactory.getBeanNamesForType(JwtDecoder.class))
                .containsExactly("jwtDecoder");
    }

    @Test
    void configuresTheJwksClientWithABoundedConnectionTimeoutAndNoRedirects() {
        assertThat(jwksHttpClient.connectTimeout()).contains(Duration.ofSeconds(2));
        assertThat(jwksHttpClient.followRedirects()).isEqualTo(HttpClient.Redirect.NEVER);
    }
}
