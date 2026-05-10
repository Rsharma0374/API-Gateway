package in.guardianservices.api_gateway.filter;

import com.nimbusds.jwt.JWTClaimsSet;
import in.guardianservices.api_gateway.exception.JwtVerificationException;
import in.guardianservices.api_gateway.security.JwtVerifier;
import in.guardianservices.api_gateway.security.PublicPathRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.util.context.Context;
import java.nio.charset.StandardCharsets;
import java.util.List;
/**
 * Second filter in the gateway chain ({@code @Order(2)}).
 *
 * <p>Enforces JWT-based authentication on all non-public routes.
 * Public routes are determined exclusively by {@link PublicPathRegistry} —
 * the single source of truth — so there is no duplicated path list here.
 *
 * <h3>Filter responsibilities</h3>
 * <ol>
 *   <li><strong>Public path bypass</strong> — delegates to {@link PublicPathRegistry}
 *       using Ant-style pattern matching so wildcards like {@code /public/**} work
 *       correctly (the original {@code List.contains()} check only handled exact paths).</li>
 *   <li><strong>Authorization header extraction</strong> — reads and validates the
 *       {@code Authorization: Bearer <token>} header.</li>
 *   <li><strong>JWT verification</strong> — delegates to {@link JwtVerifier} which
 *       handles JWKS fetch, signature verification, and claims validation.</li>
 *   <li><strong>Claims propagation</strong> — writes the verified {@link JWTClaimsSet}
 *       into the Reactor {@link Context} and as a mutated request attribute so
 *       downstream handlers (route handlers, other filters) can read them without
 *       re-parsing the token.</li>
 *   <li><strong>Structured error responses</strong> — returns RFC 7807
 *       Problem+JSON bodies for {@code 401} responses so API clients receive
 *       machine-readable error details.</li>
 * </ol>
 *
 * <h3>Claims in downstream handlers</h3>
 * After this filter runs, the verified claims are accessible two ways:
 * <pre>{@code
 * // 1. Via Reactor Context (preferred in reactive code):
 * Mono.deferContextual(ctx -> {
 *     JWTClaimsSet claims = ctx.get(JwtVerificationFilter.CLAIMS_CONTEXT_KEY);
 *     String subject = claims.getSubject();
 *     ...
 * });
 *
 * // 2. Via exchange attributes (useful in ServerRequest handlers):
 * JWTClaimsSet claims =
 *     exchange.getAttribute(JwtVerificationFilter.CLAIMS_ATTRIBUTE_KEY);
 * }</pre>
 *
 * <h3>Security hardening</h3>
 * <ul>
 *   <li>The raw JWT is never logged — only the extracted {@code sub} and
 *       {@code exp} are logged at DEBUG level after successful verification.</li>
 *   <li>Error responses contain a generic message — no internal details
 *       (stack traces, key IDs, algorithm names) are ever sent to the client.</li>
 *   <li>The filter short-circuits immediately on the first sign of a problem —
 *       no partial processing of unauthenticated requests.</li>
 * </ul>
 */
@Component
@Order(2)
public class JwtVerificationFilter implements WebFilter {
    private static final Logger log = LoggerFactory.getLogger(JwtVerificationFilter.class);
    /**
     * Reactor Context key under which the verified {@link JWTClaimsSet} is stored.
     * Readable by downstream operators via {@code ctx.get(CLAIMS_CONTEXT_KEY)}.
     */
    public static final String CLAIMS_CONTEXT_KEY = "jwtClaims";
    /**
     * Exchange attribute key under which the verified {@link JWTClaimsSet} is stored.
     * Readable by downstream route handlers via {@code exchange.getAttribute(CLAIMS_ATTRIBUTE_KEY)}.
     */
    public static final String CLAIMS_ATTRIBUTE_KEY = "gateway.jwtClaims";
    /** Expected prefix of the Authorization header value. */
    private static final String BEARER_PREFIX = "Bearer ";
    private final JwtVerifier jwtVerifier;
    private final PublicPathRegistry publicPathRegistry;
    private final String jwksUrl;
    /**
     * @param jwtVerifier        JWT verification engine — injected by Spring.
     * @param publicPathRegistry single source of truth for public paths — injected by Spring.
     * @param jwksUrl            JWKS endpoint URL — bound from {@code auth.jwt.jwks-url}.
     */
    public JwtVerificationFilter(
            JwtVerifier jwtVerifier,
            PublicPathRegistry publicPathRegistry,
            @Value("${auth.jwt.jwks-url}") String jwksUrl) {
        this.jwtVerifier = jwtVerifier;
        this.publicPathRegistry = publicPathRegistry;
        this.jwksUrl = jwksUrl;
        log.info("JwtVerificationFilter initialised — jwksUrl={}", jwksUrl);
    }
    // ─────────────────────────────────────────────────────────────────────────
    // WebFilter
    // ─────────────────────────────────────────────────────────────────────────
    /**
     * Authenticates the incoming request or short-circuits with {@code 401}.
     *
     * <p>Flow:
     * <pre>
     *   Incoming request
     *       │
     *       ▼
     *   Is path public?  ──YES──▶  chain.filter()  (no auth required)
     *       │
     *      NO
     *       │
     *       ▼
     *   Has "Authorization: Bearer <token>" header?  ──NO──▶  401 Unauthorized
     *       │
     *      YES
     *       │
     *       ▼
     *   jwtVerifier.verifyToken()
     *       │
     *   ┌───┴────────────────┐
     *  OK                 ERROR
     *   │                    │
     *   ▼                    ▼
     * Propagate claims    401 Unauthorized
     * chain.filter()
     * </pre>
     */
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        log.info("Inside Jwt verification filter for path: {}", exchange.getRequest().getURI().getPath());
        String path = exchange.getRequest().getURI().getPath();
        // ── Step 1: Public path bypass ────────────────────────────────────────
        // Uses AntPathMatcher internally — handles /public/**, /health, etc.
        if (publicPathRegistry.isPublicPath(path)) {
            log.info("Path '{}' identified as public, bypassing JWT verification", path);
            log.trace("Public path '{}' — skipping JWT verification", path);
            return chain.filter(exchange);
        }
        // ── Step 2: Extract Bearer token ─────────────────────────────────────
        String token = extractBearerToken(exchange);
        if (token == null) {
            log.info("No valid Bearer token found for path: {}", path);
            log.warn("Missing or malformed Authorization header — path={} method={}",
                    path, exchange.getRequest().getMethod());
            return unauthorized(exchange, "Missing or malformed Authorization header. "
                    + "Expected: 'Authorization: Bearer <token>'");
        }
        // ── Step 3: Verify token → propagate claims → continue chain ─────────
        log.info("Verifying JWT token for path: {}", path);
        return jwtVerifier.verifyToken(token, jwksUrl)
                .flatMap(claims -> propagateAndContinue(exchange, chain, claims))
                .onErrorResume(JwtVerificationException.class, ex -> {
                    // Verification-specific failure — log with detail internally,
                    // return generic 401 externally (never expose internals).
                    log.info("JWT verification failed for path: {}", path);
                    log.warn("JWT verification failed — path={} reason={}",
                            path, ex.getMessage());
                    return unauthorized(exchange, "Authentication failed. "
                            + "Token is missing, expired, or invalid.");
                })
                .onErrorResume(ex -> {
                    // Unexpected infrastructure failure (e.g. JWKS unreachable).
                    log.info("Unexpected error during JWT verification for path: {}", path);
                    log.error("Unexpected error during JWT verification — path={}",
                            path, ex);
                    return serviceUnavailable(exchange,
                            "Authentication service temporarily unavailable. "
                                    + "Please retry shortly.");
                });
    }
    // ─────────────────────────────────────────────────────────────────────────
    // Claims propagation
    // ─────────────────────────────────────────────────────────────────────────
    /**
     * Stores the verified claims in two places and continues the filter chain:
     * <ol>
     *   <li>As a mutable exchange attribute — for non-reactive downstream handlers.</li>
     *   <li>In the Reactor {@link Context} — for reactive downstream operators.</li>
     * </ol>
     */
    private Mono<Void> propagateAndContinue(
            ServerWebExchange exchange,
            WebFilterChain chain,
            JWTClaimsSet claims) {
        // Store as exchange attribute — readable by any downstream handler
        // via exchange.getAttribute(CLAIMS_ATTRIBUTE_KEY).
        exchange.getAttributes().put(CLAIMS_ATTRIBUTE_KEY, claims);
        log.info("Propagating JWT claims for subject: {}", safeSubject(claims));
        log.debug("JWT claims propagated — sub={} path={}",
                safeSubject(claims),
                exchange.getRequest().getURI().getPath());
        // Store in Reactor Context — readable by reactive downstream operators.
        // contextWrite() is placed last because Reactor propagates context
        // upstream through the operator chain.
        return chain.filter(exchange)
                .contextWrite(Context.of(CLAIMS_CONTEXT_KEY, claims));
    }
    // ─────────────────────────────────────────────────────────────────────────
    // Token extraction
    // ─────────────────────────────────────────────────────────────────────────
    /**
     * Extracts the raw JWT string from the {@code Authorization} header.
     *
     * <p>Returns {@code null} if:
     * <ul>
     *   <li>The header is absent.</li>
     *   <li>The header value does not start with {@code "Bearer "}.</li>
     *   <li>The token segment after {@code "Bearer "} is blank.</li>
     * </ul>
     *
     * @param exchange the current server web exchange
     * @return the raw JWT string, or {@code null} if extraction fails
     */
    private String extractBearerToken(ServerWebExchange exchange) {
        List<String> authHeaders = exchange.getRequest()
                .getHeaders()
                .getOrDefault(HttpHeaders.AUTHORIZATION, List.of());
        if (authHeaders.isEmpty()) {
            return null;
        }
        String authHeader = authHeaders.get(0);
        if (!authHeader.startsWith(BEARER_PREFIX)) {
            return null;
        }
        String token = authHeader.substring(BEARER_PREFIX.length()).strip();
        return token.isBlank() ? null : token;
    }
    // ─────────────────────────────────────────────────────────────────────────
    // Error responses — RFC 7807 Problem+JSON
    // ─────────────────────────────────────────────────────────────────────────
    /**
     * Writes a {@code 401 Unauthorized} response with an RFC 7807
     * {@code application/problem+json} body.
     *
     * <p>The response body is intentionally generic — no internal details
     * (key IDs, algorithm names, stack traces) are ever exposed to the client.
     */
    private Mono<Void> unauthorized(ServerWebExchange exchange, String detail) {
        log.info("Returning 401 Unauthorized for path: {}", exchange.getRequest().getURI().getPath());
        return writeProblemJson(exchange, HttpStatus.UNAUTHORIZED,
                "https://httpstatuses.com/401",
                "Unauthorized",
                detail);
    }
    /**
     * Writes a {@code 503 Service Unavailable} response when the authentication
     * infrastructure (e.g. JWKS endpoint) is temporarily unreachable.
     */
    private Mono<Void> serviceUnavailable(ServerWebExchange exchange, String detail) {
        log.info("Returning 503 Service Unavailable for path: {}", exchange.getRequest().getURI().getPath());
        return writeProblemJson(exchange, HttpStatus.SERVICE_UNAVAILABLE,
                "https://httpstatuses.com/503",
                "Service Unavailable",
                detail);
    }
    /**
     * Writes an RFC 7807 Problem+JSON response body.
     *
     * <p>Example response body:
     * <pre>{@code
     * {
     *   "type":   "https://httpstatuses.com/401",
     *   "title":  "Unauthorized",
     *   "status": 401,
     *   "detail": "Authentication failed. Token is missing, expired, or invalid."
     * }
     * }</pre>
     *
     * @param exchange  the current exchange
     * @param status    HTTP status to set on the response
     * @param type      URI reference identifying the problem type
     * @param title     short, human-readable problem summary
     * @param detail    human-readable explanation of this specific occurrence
     */
    private Mono<Void> writeProblemJson(
            ServerWebExchange exchange,
            HttpStatus status,
            String type,
            String title,
            String detail) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(status);
        response.getHeaders().setContentType(MediaType.APPLICATION_PROBLEM_JSON);
        // Read requestId from Reactor Context for client-side correlation.
        return Mono.deferContextual(ctx -> {
            String requestId = ctx.getOrDefault(
                    RequestIdFilter.REQUEST_ID_CONTEXT_KEY, "none");
            String body = String.format(
                    """
                    {
                      "type":      "%s",
                      "title":     "%s",
                      "status":    %d,
                      "detail":    "%s",
                      "requestId": "%s"
                    }
                    """,
                    type, title, status.value(), detail, requestId);
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            DataBuffer buffer = response.bufferFactory().wrap(bytes);
            return response.writeWith(Mono.just(buffer));
        });
    }
    // ─────────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────────
    /**
     * Safely extracts the {@code sub} claim for logging — never throws.
     * If extraction fails the returned string is {@code "<unknown>"}.
     */
    private String safeSubject(JWTClaimsSet claims) {
        try {
            String sub = claims.getSubject();
            return sub != null ? sub : "<none>";
        } catch (Exception ex) {
            return "<unknown>";
        }
    }
}