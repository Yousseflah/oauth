package io.github.yousseflah.oauth.resource.config;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;

final class SubjectValidator implements OAuth2TokenValidator<Jwt> {

    private static final OAuth2Error INVALID_SUBJECT = new OAuth2Error(
            OAuth2ErrorCodes.INVALID_TOKEN,
            "The token subject is invalid",
            null);

    @Override
    public OAuth2TokenValidatorResult validate(Jwt token) {
        var subjectClaim = token.getClaims().get(JwtClaimNames.SUB);
        if (subjectClaim instanceof String subject && !subject.isBlank()) {
            return OAuth2TokenValidatorResult.success();
        }

        return OAuth2TokenValidatorResult.failure(INVALID_SUBJECT);
    }
}
