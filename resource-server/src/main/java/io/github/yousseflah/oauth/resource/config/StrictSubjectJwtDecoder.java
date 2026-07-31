package io.github.yousseflah.oauth.resource.config;

import java.text.ParseException;

import com.nimbusds.jose.JWSObject;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;

final class StrictSubjectJwtDecoder implements JwtDecoder {

    private static final String INVALID_SUBJECT_TYPE =
            "An error occurred while attempting to decode the Jwt: The token subject must be a string";

    private final JwtDecoder delegate;

    StrictSubjectJwtDecoder(JwtDecoder delegate) {
        this.delegate = delegate;
    }

    @Override
    public Jwt decode(String token) {
        var jwt = delegate.decode(token);

        try {
            // Nimbus normalizes some registered claims; inspect the authenticated JWS payload for strict typing.
            var rawClaims = JWSObject.parse(token).getPayload().toJSONObject();
            if (rawClaims == null || !(rawClaims.get(JwtClaimNames.SUB) instanceof String)) {
                throw new BadJwtException(INVALID_SUBJECT_TYPE);
            }
        } catch (ParseException exception) {
            throw new BadJwtException("An error occurred while attempting to decode the Jwt: Malformed token", exception);
        }

        return jwt;
    }
}
