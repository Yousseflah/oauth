package io.github.yousseflah.oauth.authorization.token;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/tokens")
final class TokenController {

    private static final String BEARER_TOKEN_TYPE = "Bearer";

    private final TokenService tokenService;

    TokenController(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @PostMapping(
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    TokenResponse issueToken(@RequestParam("subject") String subject) {
        var issuedToken = tokenService.issueToken(subject);
        return new TokenResponse(
                issuedToken.accessToken(),
                BEARER_TOKEN_TYPE,
                issuedToken.expiresInSeconds());
    }
}
