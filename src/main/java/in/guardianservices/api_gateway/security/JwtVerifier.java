package in.guardianservices.api_gateway.security;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import in.guardianservices.api_gateway.exception.JwtVerificationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Set;
/**
 * Reactive JWT verifier that validates incoming Bearer tokens against a
 * remote JWKS (JSON Web Key Set) endpoint.
 *
 * <h3>Verification pipeline (in order)</h3>
 * <ol>
 *   <li>Parse and structurally validate the JWT (3-part Base64URL).</li>
 *   <li>Extract the {@code kid} (Key ID) from the JOSE header.</li>
 *   <li>Fetch (or load from cache) the JWKS JSON via {@link JwksCache}.</li>
 *   <li>Locate the matching key by {@code kid} in the key set.</li>
 *   <li>Verify the cryptographic signature (RSA or EC).</li>
 *   <li>Validate standard claims: {@code exp}, {@code nbf}, {@code iss}, {@code aud}.</li>
 *   <li>Return the validated {@link JWTClaimsSet} to the caller.</li>
 * </ol>
 *
 * <h3>Key rotation support</h3>
 * If the JWKS contains no key matching the JWT's {@code kid}, the cache entry
 * is forcibly invalidated and the JWKS is re-fetched exactly once.  This
 * handles identity-provider key rotations transparently without restarting
 * the gateway.
 *
 * <h3>Algorithm support</h3>
 * RSA (RS256, RS384, RS512) and EC (ES256, ES384, ES512) are both supported.
 * Symmetric algorithms (HS256 etc.) are intentionally rejected — they require
 * sharing a secret with every client, which is inappropriate for a gateway.
 *
 * <h3>Threading</h3>
 * JWKS parsing and JWT verification are CPU-bound but blocking operations
 * (Nimbus JOSE+JWT is synchronous).  They are executed on
 * {@link Schedulers#boundedElastic()} so they never block a Netty I/O thread.
 */
@Component
public class JwtVerifier {

    private static final Logger log = LoggerFactory.getLogger(JwtVerifier.class);

    /**
     * Maximum clock skew tolerated when validating {@code exp} and {@code nbf}.
     * 30 seconds is a widely accepted industry default.
     */
    private static final long CLOCK_SKEW_SECONDS = 30;

    /**
     * Algorithms explicitly rejected to prevent algorithm-confusion attacks.
     * "none" allows unsigned JWTs; symmetric algorithms share a secret.
     */
    private static final Set<String> REJECTED_ALGORITHMS =
            Set.of("none", "HS256", "HS384", "HS512");

    private final JwksCache jwksCache;
    private final String expectedIssuer;
    private final String expectedAudience;
    private final Clock clock;

    /**
     * @param jwksCache        JWKS cache — injected by Spring.
     * @param expectedIssuer   value of the {@code iss} claim that all JWTs must carry.
     * @param expectedAudience value of the {@code aud} claim that all JWTs must include.
     * @param clock            system clock — injectable for deterministic unit testing.
     */
    public JwtVerifier(
            JwksCache jwksCache,
            @Value("${auth.jwt.issuer}") String expectedIssuer,
            @Value("${auth.jwt.audience}") String expectedAudience,
            Clock clock) {
        log.info("Initializing JwtVerifier");
        this.jwksCache = jwksCache;
        this.expectedIssuer = expectedIssuer;
        this.expectedAudience = expectedAudience;
        this.clock = clock;
        log.info("JwtVerifier initialised — issuer={}, audience={}",
                expectedIssuer, expectedAudience);
    }
    // ─────────────────────────────────────────────────────────────────────────
    // Public API
    // ─────────────────────────────────────────────────────────────────────────
    /**
     * Fully verifies a raw Bearer token string and returns its claims.
     *
     * <p>This method is the sole entry point for JWT verification.  It is
     * intentionally stateless — all state lives in {@link JwksCache}.
     *
     * @param rawToken  the raw JWT string (without the {@code "Bearer "} prefix)
     * @param jwksUrl   the JWKS endpoint URL to validate against
     * @return a {@link Mono} emitting the validated {@link JWTClaimsSet},
     *         or an error signal carrying a {@link JwtVerificationException}
     */
    public Mono<JWTClaimsSet> verifyToken(String rawToken, String jwksUrl) {
        log.info("Starting JWT token verification process");
        if (rawToken == null || rawToken.isBlank()) {
            log.info("Token is null or blank, aborting verification");
            return Mono.error(new JwtVerificationException("Token must not be null or blank"));
        }
        return parseJwt(rawToken)
                .flatMap(signedJwt -> verifyWithJwks(signedJwt, jwksUrl, false))
                .flatMap(this::validateClaims)
                .doOnNext(claims -> log.info("JWT verified successfully for subject: {}", safeSub(claims)))
                .doOnNext(claims -> log.debug(
                        "JWT verified successfully — sub={}, exp={}",
                        safeSub(claims), safeExp(claims)))
                .doOnError(ex -> log.info("JWT verification failed: {}", ex.getMessage()))
                .doOnError(ex -> log.warn(
                        "JWT verification failed — reason={}", ex.getMessage()));
    }
    // ─────────────────────────────────────────────────────────────────────────
    // Step 1 — Parse
    // ─────────────────────────────────────────────────────────────────────────
    /**
     * Parses the raw token string into a {@link SignedJWT}, rejecting:
     * <ul>
     *   <li>Malformed Base64URL structure.</li>
     *   <li>Unsigned ({@code "none"}) and symmetric (HS*) algorithms.</li>
     * </ul>
     */
    private Mono<SignedJWT> parseJwt(String rawToken) {
        log.info("Parsing JWT token");
        return Mono.fromCallable(() -> {
            SignedJWT signedJWT;
            try {
                signedJWT = SignedJWT.parse(rawToken);
            } catch (ParseException ex) {
                log.info("Failed to parse JWT: {}", ex.getMessage());
                throw new JwtVerificationException("Malformed JWT — could not parse: " + ex.getMessage(), ex);
            }
            String algorithm = signedJWT.getHeader().getAlgorithm().getName();
            if (REJECTED_ALGORITHMS.contains(algorithm)) {
                log.info("Rejected JWT algorithm: {}", algorithm);
                throw new JwtVerificationException(
                        "Rejected JWT algorithm '" + algorithm + "' — only RSA and EC are permitted");
            }
            String kid = signedJWT.getHeader().getKeyID();
            if (kid == null || kid.isBlank()) {
                log.info("JWT header is missing 'kid'");
                throw new JwtVerificationException("JWT header is missing the 'kid' (Key ID) field");
            }
            log.info("JWT parsed successfully with algorithm={} and kid={}", algorithm, kid);
            log.debug("Parsed JWT — algorithm={}, kid={}", algorithm, kid);
            return signedJWT;
        }).subscribeOn(Schedulers.boundedElastic());
    }
    // ─────────────────────────────────────────────────────────────────────────
    // Step 2 — Fetch JWKS + Verify Signature
    // ─────────────────────────────────────────────────────────────────────────
    /**
     * Fetches the JWKS, finds the key matching the JWT's {@code kid}, and
     * verifies the signature.
     *
     * <p>If no matching key is found on the first attempt and {@code isRetry}
     * is {@code false}, the cache is invalidated and one retry is performed.
     * This transparently handles key rotation without any manual intervention.
     *
     * @param signedJwt the parsed JWT to verify
     * @param jwksUrl   the JWKS endpoint URL
     * @param isRetry   {@code true} if this is a post-invalidation retry attempt
     */
    private Mono<SignedJWT> verifyWithJwks(SignedJWT signedJwt, String jwksUrl, boolean isRetry) {
        log.info("Verifying JWT signature with JWKS from {}", jwksUrl);
        return jwksCache.getJwks(jwksUrl)
                .flatMap(jwksJson -> parseJwkSet(jwksJson, jwksUrl))
                .flatMap(jwkSet -> {
                    String kid = signedJwt.getHeader().getKeyID();
                    JWK matchingKey = jwkSet.getKeyByKeyId(kid);
                    if (matchingKey == null) {
                        if (isRetry) {
                            // Already retried — the key genuinely doesn't exist.
                            log.info("Key not found in JWKS for kid={} after retry", kid);
                            return Mono.error(new JwtVerificationException(
                                    "No key found in JWKS for kid='" + kid
                                            + "' after cache refresh — possible invalid token"));
                        }
                        // First attempt: invalidate cache and retry once.
                        log.info("kid='{}' not found in cached JWKS — invalidating and retrying", kid);
                        jwksCache.invalidate(jwksUrl);
                        return verifyWithJwks(signedJwt, jwksUrl, true);
                    }
                    return verifySignature(signedJwt, matchingKey);
                });
    }
    /**
     * Parses the raw JWKS JSON string into a Nimbus {@link JWKSet}.
     * Runs on {@link Schedulers#boundedElastic()} as Nimbus parsing is synchronous.
     */
    private Mono<JWKSet> parseJwkSet(String jwksJson, String jwksUrl) {
        return Mono.fromCallable(() -> {
            try {
                return JWKSet.parse(jwksJson);
            } catch (ParseException ex) {
                log.info("Failed to parse JWKS from {}: {}", jwksUrl, ex.getMessage());
                throw new JwtVerificationException(
                        "Failed to parse JWKS from url=" + jwksUrl + ": " + ex.getMessage(), ex);
            }
        }).subscribeOn(Schedulers.boundedElastic());
    }
    /**
     * Cryptographically verifies the JWT signature using the resolved JWK.
     *
     * <p>Supported key types:
     * <ul>
     *   <li>{@link RSAKey} — RS256, RS384, RS512</li>
     *   <li>{@link ECKey} — ES256, ES384, ES512</li>
     * </ul>
     *
     * @throws JwtVerificationException for unsupported key types or invalid signatures
     */
    private Mono<SignedJWT> verifySignature(SignedJWT signedJwt, JWK jwk) {
        log.info("Verifying signature with key type {}", jwk.getKeyType().getValue());
        return Mono.fromCallable(() -> {
            try {
                boolean valid;
                String keyType = jwk.getKeyType().getValue();
                if (jwk instanceof RSAKey rsaKey) {
                    // Java 21 pattern matching for instanceof
                    RSAPublicKey rsaPublicKey = rsaKey.toRSAPublicKey();
                    RSASSAVerifier verifier = new RSASSAVerifier(rsaPublicKey);
                    valid = signedJwt.verify(verifier);
                } else if (jwk instanceof ECKey ecKey) {
                    ECPublicKey ecPublicKey = ecKey.toECPublicKey();
                    ECDSAVerifier verifier = new ECDSAVerifier(ecPublicKey);
                    valid = signedJwt.verify(verifier);
                } else {
                    log.info("Unsupported JWK key type: {}", keyType);
                    throw new JwtVerificationException(
                            "Unsupported JWK key type '" + keyType
                                    + "' — only RSA and EC are supported");
                }
                if (!valid) {
                    log.info("Signature verification failed for kid='{}'", jwk.getKeyID());
                    throw new JwtVerificationException(
                            "JWT signature verification failed for kid='"
                                    + jwk.getKeyID() + "'");
                }
                log.info("Signature successfully verified for kid={}", jwk.getKeyID());
                log.debug("Signature verified — kid={}, keyType={}", jwk.getKeyID(), keyType);
                return signedJwt;
            } catch (JwtVerificationException ex) {
                throw ex; // re-throw our own exceptions as-is
            } catch (Exception ex) {
                log.info("Unexpected error during signature verification: {}", ex.getMessage());
                throw new JwtVerificationException(
                        "Unexpected error during signature verification: " + ex.getMessage(), ex);
            }
        }).subscribeOn(Schedulers.boundedElastic());
    }
    // ─────────────────────────────────────────────────────────────────────────
    // Step 3 — Validate Claims
    // ─────────────────────────────────────────────────────────────────────────
    /**
     * Validates standard JWT claims after signature verification succeeds:
     *
     * <ul>
     *   <li>{@code exp} — token must not be expired (with clock-skew tolerance).</li>
     *   <li>{@code nbf} — token must not be used before its valid start time.</li>
     *   <li>{@code iss} — issuer must match {@code auth.jwt.issuer} config.</li>
     *   <li>{@code aud} — audience must contain {@code auth.jwt.audience} config.</li>
     * </ul>
     *
     * @param signedJwt the signature-verified JWT
     * @return a {@link Mono} emitting the {@link JWTClaimsSet} if all claims pass
     */
    private Mono<JWTClaimsSet> validateClaims(SignedJWT signedJwt) {
        log.info("Validating JWT claims");
        return Mono.fromCallable(() -> {
            JWTClaimsSet claims;
            try {
                claims = signedJwt.getJWTClaimsSet();
            } catch (ParseException ex) {
                log.info("Could not extract claims: {}", ex.getMessage());
                throw new JwtVerificationException("Could not extract claims from JWT: " + ex.getMessage(), ex);
            }
            Instant now = clock.instant();
            // ── Expiry (exp) ──────────────────────────────────────────────────
            Date expiration = claims.getExpirationTime();
            if (expiration == null) {
                log.info("JWT missing required 'exp' claim");
                throw new JwtVerificationException("JWT is missing required 'exp' claim");
            }
            if (now.minusSeconds(CLOCK_SKEW_SECONDS).isAfter(expiration.toInstant())) {
                log.info("JWT has expired");
                throw new JwtVerificationException(
                        "JWT has expired — exp=" + expiration.toInstant()
                                + ", now=" + now + ", skew=" + CLOCK_SKEW_SECONDS + "s");
            }
            // ── Not Before (nbf) ─────────────────────────────────────────────
            Date notBefore = claims.getNotBeforeTime();
            if (notBefore != null) {
                if (now.plusSeconds(CLOCK_SKEW_SECONDS).isBefore(notBefore.toInstant())) {
                    log.info("JWT is not yet valid (nbf)");
                    throw new JwtVerificationException(
                            "JWT is not yet valid — nbf=" + notBefore.toInstant()
                                    + ", now=" + now + ", skew=" + CLOCK_SKEW_SECONDS + "s");
                }
            }
            // ── Issuer (iss) ──────────────────────────────────────────────────
            String issuer = claims.getIssuer();
            if (issuer == null || !expectedIssuer.equals(issuer)) {
                log.info("JWT issuer mismatch: expected='{}', got='{}'", expectedIssuer, issuer);
                throw new JwtVerificationException(
                        "JWT issuer mismatch — expected='" + expectedIssuer
                                + "', got='" + issuer + "'");
            }
            // ── Audience (aud) ────────────────────────────────────────────────
            List<String> audience = claims.getAudience();
            if (audience == null || audience.isEmpty()) {
                log.info("JWT missing required 'aud' claim");
                throw new JwtVerificationException("JWT is missing required 'aud' claim");
            }
            if (!audience.contains(expectedAudience)) {
                log.info("JWT audience mismatch: expected='{}', got={}", expectedAudience, audience);
                throw new JwtVerificationException(
                        "JWT audience mismatch — expected='" + expectedAudience
                                + "', got=" + audience);
            }
            // ── Subject (sub) — must be present ──────────────────────────────
            String subject = claims.getSubject();
            if (subject == null || subject.isBlank()) {
                log.info("JWT missing required 'sub' claim");
                throw new JwtVerificationException("JWT is missing required 'sub' claim");
            }
            log.info("Claims validated successfully for subject: {}", subject);
            log.debug("Claims validated — sub={}, iss={}, aud={}, exp={}",
                    subject, issuer, audience, expiration.toInstant());
            return claims;
        }).subscribeOn(Schedulers.boundedElastic());
    }
    // ─────────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────────
    /** Safely extracts subject for logging — never throws. */
    private String safeSub(JWTClaimsSet claims) {
        try {
            return claims.getSubject();
        } catch (Exception e) {
            return "<unknown>";
        }
    }
    /** Safely extracts expiry for logging — never throws. */
    private String safeExp(JWTClaimsSet claims) {
        try {
            Date exp = claims.getExpirationTime();
            return exp != null ? exp.toInstant().toString() : "<none>";
        } catch (Exception e) {
            return "<unknown>";
        }
    }
}