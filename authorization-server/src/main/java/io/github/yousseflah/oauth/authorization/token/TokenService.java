package io.github.yousseflah.oauth.authorization.token;

import java.time.Clock;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;

import io.github.yousseflah.oauth.authorization.config.AuthorizationProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.stereotype.Service;

@Service
final class TokenService {

    private static final Logger LOGGER = LoggerFactory.getLogger(TokenService.class);

    private final JwtEncoder jwtEncoder;
    private final AuthorizationProperties properties;
    private final SubjectValidator subjectValidator;
    private final Clock clock;

    TokenService(
            JwtEncoder jwtEncoder,
            AuthorizationProperties properties,
            SubjectValidator subjectValidator,
            Clock clock) {
        this.jwtEncoder = jwtEncoder;
        this.properties = properties;
        this.subjectValidator = subjectValidator;
        this.clock = clock;
    }

    IssuedToken issueToken(String subject) {
        var normalizedSubject = subjectValidator.normalize(subject);
        var issuedAt = clock.instant().truncatedTo(ChronoUnit.SECONDS);
        var expiresAt = issuedAt.plus(properties.accessTokenTtl());
        var tokenId = UUID.randomUUID().toString();

        var headers = JwsHeader.with(SignatureAlgorithm.RS256)
                .type(properties.tokenType())
                .build();
        var claims = JwtClaimsSet.builder()
                .issuer(properties.issuer().toString())
                .subject(normalizedSubject)
                .audience(List.of(properties.audience()))
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                .id(tokenId)
                .build();
        var jwt = jwtEncoder.encode(JwtEncoderParameters.from(headers, claims));

        LOGGER.info("Issued access token with jti={} and expiresAt={}", tokenId, expiresAt);
        return new IssuedToken(jwt.getTokenValue(), properties.accessTokenTtl().toSeconds());
    }
}
