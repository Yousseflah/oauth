package io.github.yousseflah.oauth.resource.hello;

import org.springframework.http.MediaType;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
final class HelloController {

    @GetMapping(value = "/api/v1/hello", produces = MediaType.APPLICATION_JSON_VALUE)
    HelloResponse hello(@AuthenticationPrincipal Jwt jwt) {
        return new HelloResponse("Hello, %s!".formatted(jwt.getSubject()));
    }
}
