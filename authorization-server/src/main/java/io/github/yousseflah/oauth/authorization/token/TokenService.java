package io.github.yousseflah.oauth.authorization.token;

import java.time.Clock;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;

import io.github.yousseflah.oauth.authorization.config.AuthorizationSecurityProperties;
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
    private final AuthorizationSecurityProperties securityProperties;
    private final SubjectNormalizer subjectNormalizer;
    private final Clock clock;

    TokenService(
            JwtEncoder jwtEncoder,
            AuthorizationSecurityProperties securityProperties,
            SubjectNormalizer subjectNormalizer,
            Clock clock) {
        this.jwtEncoder = jwtEncoder;
        this.securityProperties = securityProperties;
        this.subjectNormalizer = subjectNormalizer;
        this.clock = clock;
    }

    IssuedToken issueToken(String subject) {
        var normalizedSubject = subjectNormalizer.normalize(subject);
        var accessTokenTtl = securityProperties.accessTokenTtl();
        var issuedAt = clock.instant().truncatedTo(ChronoUnit.SECONDS);
        var expiresAt = issuedAt.plus(accessTokenTtl);
        var tokenId = UUID.randomUUID().toString();

        var headers = JwsHeader.with(SignatureAlgorithm.RS256)
                .type(securityProperties.tokenType())
                .build();
        var claims = JwtClaimsSet.builder()
                .issuer(securityProperties.issuer().toString())
                .subject(normalizedSubject)
                .audience(List.of(securityProperties.audience()))
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                .id(tokenId)
                .build();
        var jwt = jwtEncoder.encode(JwtEncoderParameters.from(headers, claims));

        LOGGER.info("Issued access token with jti={} and expiresAt={}", tokenId, expiresAt);
        return new IssuedToken(jwt.getTokenValue(), accessTokenTtl.toSeconds());
    }
}
