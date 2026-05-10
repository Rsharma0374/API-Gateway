package in.guardianservices.api_gateway.config;

import com.nimbusds.jwt.JWTClaimsSet;
import in.guardianservices.api_gateway.filter.JwtVerificationFilter;
import in.guardianservices.api_gateway.filter.RequestIdFilter;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import io.github.resilience4j.reactor.circuitbreaker.operator.CircuitBreakerOperator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import static org.springframework.web.reactive.function.server.RequestPredicates.GET;
import static org.springframework.web.reactive.function.server.RequestPredicates.POST;
/**
 * Functional route configuration for the API Gateway.
 *
 * <p>Defines all internal gateway routes using Spring WebFlux's functional
 * router DSL ({@link RouterFunctions}).  Each route is a pure function —
 * no annotations, no controller classes — making them easy to test, compose,
 * and reason about.
 *
 * <h3>Routes defined</h3>
 * <ul>
 *   <li>{@code GET  /health}          — liveness probe (public)</li>
 *   <li>{@code GET  /actuator/**}     — Spring Boot Actuator (restricted in prod
 *                                       to internal network via firewall/ingress)</li>
 *   <li>{@code GET  /fallback/**}     — circuit-breaker fallback endpoint (public)</li>
 *   <li>{@code GET  /public/**}       — publicly accessible resources (public)</li>
 *   <li>{@code GET  /api/**}          — authenticated API routes (JWT required)</li>
 *   <li>{@code POST /api/**}          — authenticated API routes (JWT required)</li>
 * </ul>
 *
 * <h3>Circuit breaker</h3>
 * The {@code /api/**} routes are wrapped in a Resilience4j
 * {@link CircuitBreaker} named {@code "downstreamService"}.  When the
 * downstream service is unavailable (circuit open), requests are
 * automatically redirected to the {@code /fallback/**} endpoint.
 *
 * <h3>Claims propagation</h3>
 * Route handlers for authenticated paths read the verified
 * {@link JWTClaimsSet} from the Reactor Context (set by
 * {@link JwtVerificationFilter}) to extract the authenticated subject
 * for logging and downstream header propagation.
 *
 * <h3>Why functional routes over {@code @Controller}?</h3>
 * <ul>
 *   <li>No reflection — fully compatible with GraalVM native image.</li>
 *   <li>Composable and testable without starting a full Spring context.</li>
 *   <li>Explicit request matching — no ambiguous path variable collisions.</li>
 *   <li>Fine-grained error handling per route via {@code onErrorResume}.</li>
 * </ul>
 */
@Configuration
public class RouteConfig {
    private static final Logger log = LoggerFactory.getLogger(RouteConfig.class);
    /** Name of the circuit breaker protecting downstream API calls. */
    private static final String DOWNSTREAM_CB_NAME = "downstreamService";
    /**
     * Header forwarded to downstream services identifying the authenticated caller.
     * Downstream services trust this header only because the gateway has already
     * verified the JWT — never accept this header from untrusted sources.
     */
    private static final String DOWNSTREAM_SUBJECT_HEADER = "X-Authenticated-Subject";
    // ─────────────────────────────────────────────────────────────────────────
    // Router
    // ─────────────────────────────────────────────────────────────────────────
    /**
     * Composes all gateway routes into a single {@link RouterFunction}.
     *
     * <p>Route matching is evaluated in declaration order — the first match wins.
     * More specific paths (e.g. {@code /health}) are declared before wildcards
     * (e.g. {@code /api/**}) to prevent shadowing.
     *
     * @param cbRegistry Resilience4j circuit-breaker registry — auto-configured
     *                   by the {@code resilience4j-spring-boot3} starter.
     * @return the composed router function for the entire gateway
     */
    @Bean
    public RouterFunction<ServerResponse> gatewayRouterFunction(
            CircuitBreakerRegistry cbRegistry) {
        log.info("Initializing gatewayRouterFunction bean");
        CircuitBreaker downstreamCb = buildDownstreamCircuitBreaker(cbRegistry);
        return RouterFunctions
                // ── Public routes (no JWT required) ──────────────────────────
                .route(GET("/health"),
                        req -> handleHealth(req))
                .andRoute(GET("/doc-service/**"),
                        request -> forwardToService("http://localhost:10005", "/doc-service/welcome"))
                .andRoute(GET("/fallback/**"),
                        req -> handleFallback(req))
                .andRoute(GET("/public/**"),
                        req -> handlePublic(req))
                // ── Authenticated API routes ───────────────────────────────────
                // These routes run AFTER the JwtVerificationFilter has already
                // verified the token and placed claims in the Reactor Context.
                // Handlers can safely read claims without re-verifying anything.
                .andRoute(GET("/api/**"),
                        req -> handleApiRequest(req, downstreamCb))
                .andRoute(POST("/api/**"),
                        req -> handleApiRequest(req, downstreamCb))
                // ── Catch-all: 404 for unmatched routes ───────────────────────
                .andRoute(req -> true,
                        req -> handleNotFound(req));
    }

    private Mono<ServerResponse> forwardToService(String baseUrl, String path) {
        return WebClient.create(baseUrl)
                .get()
                .uri(path)
                .retrieve()
                .bodyToMono(String.class)
                .flatMap(body -> ServerResponse.ok().bodyValue(body));
    }
    // ─────────────────────────────────────────────────────────────────────────
    // Route handlers
    // ─────────────────────────────────────────────────────────────────────────
    /**
     * Liveness probe endpoint.
     *
     * <p>Returns {@code 200 OK} with a JSON body indicating the gateway is alive.
     * Used by Kubernetes {@code livenessProbe} — must never require authentication
     * and must respond within 1 second even under load.
     *
     * <p>This route is registered in {@code gateway.public-paths} in
     * {@code application.yml} so the JWT filter skips it automatically.
     */
    private Mono<ServerResponse> handleHealth(ServerRequest request) {
        return Mono.deferContextual(ctx -> {
            String requestId = ctx.getOrDefault(
                    RequestIdFilter.REQUEST_ID_CONTEXT_KEY, "none");
            log.info("Handling health check request — requestId={}", requestId);
            log.debug("Health check — requestId={}", requestId);
            String body = String.format("""
                    {
                      "status":    "UP",
                      "timestamp": "%s",
                      "requestId": "%s"
                    }
                    """, Instant.now(), requestId);
            return ServerResponse.ok()
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(body);
        });
    }
    /**
     * Circuit-breaker fallback endpoint.
     *
     * <p>Serves a degraded-mode response when the downstream service is
     * unavailable (circuit open).  Returns {@code 503 Service Unavailable}
     * with an RFC 7807 Problem+JSON body so clients know to retry later.
     *
     * <p>The path suffix after {@code /fallback/} is used to identify which
     * downstream route triggered the fallback — useful for targeted alerting.
     */
    private Mono<ServerResponse> handleFallback(ServerRequest request) {
        return Mono.deferContextual(ctx -> {
            String requestId = ctx.getOrDefault(
                    RequestIdFilter.REQUEST_ID_CONTEXT_KEY, "none");
            String triggeredBy = request.path().replaceFirst("^/fallback", "");
            log.info("Handling fallback request — triggeredBy={} requestId={}", triggeredBy, requestId);
            log.warn("Fallback triggered — triggeredBy={} requestId={}",
                    triggeredBy, requestId);
            String body = String.format("""
                    {
                      "type":       "https://httpstatuses.com/503",
                      "title":      "Service Unavailable",
                      "status":     503,
                      "detail":     "The requested service is temporarily unavailable. Please retry shortly.",
                      "triggeredBy": "%s",
                      "requestId":  "%s"
                    }
                    """, triggeredBy, requestId);
            return ServerResponse
                    .status(HttpStatus.SERVICE_UNAVAILABLE)
                    .contentType(MediaType.APPLICATION_PROBLEM_JSON)
                    .bodyValue(body);
        });
    }
    /**
     * Public resource endpoint.
     *
     * <p>Serves resources that are intentionally accessible without
     * authentication (e.g. API documentation, OpenAPI spec, login pages).
     * Extend this handler to proxy to a dedicated public-content service.
     */
    private Mono<ServerResponse> handlePublic(ServerRequest request) {
        return Mono.deferContextual(ctx -> {
            String requestId = ctx.getOrDefault(
                    RequestIdFilter.REQUEST_ID_CONTEXT_KEY, "none");
            String resourcePath = request.path();
            log.info("Handling public resource request — path={} requestId={}", resourcePath, requestId);
            log.debug("Public resource request — path={} requestId={}",
                    resourcePath, requestId);
            String body = String.format("""
                    {
                      "path":      "%s",
                      "requestId": "%s",
                      "message":   "Public resource served successfully."
                    }
                    """, resourcePath, requestId);
            return ServerResponse.ok()
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(body);
        });
    }
    /**
     * Authenticated API route handler.
     *
     * <p>This handler is only reached after {@link JwtVerificationFilter} has
     * successfully verified the JWT and written the {@link JWTClaimsSet} into
     * the Reactor Context.  It is safe to read and trust the claims here.
     *
     * <p>Responsibilities:
     * <ol>
     *   <li>Read the authenticated subject from the Reactor Context.</li>
     *   <li>Forward the subject to the downstream service via the
     *       {@value #DOWNSTREAM_SUBJECT_HEADER} header.</li>
     *   <li>Apply the circuit breaker — redirect to {@code /fallback/**}
     *       when the downstream service is unavailable.</li>
     *   <li>Return the downstream response to the client.</li>
     * </ol>
     *
     * <p>In a real implementation, replace the stub response body with an
     * actual {@link org.springframework.web.reactive.function.client.WebClient}
     * call to the target microservice, forwarding the validated subject header.
     *
     * @param request      the incoming authenticated server request
     * @param circuitBreaker the circuit breaker protecting the downstream call
     */
    private Mono<ServerResponse> handleApiRequest(
            ServerRequest request,
            CircuitBreaker circuitBreaker) {
        return Mono.deferContextual(ctx -> {
            String requestId = ctx.getOrDefault(
                    RequestIdFilter.REQUEST_ID_CONTEXT_KEY, "none");
            String subject   = resolveSubject(ctx);
            String path      = request.path();
            String method    = request.method().name();
            log.info("API request handling started — method={} path={} subject={} requestId={}",
                    method, path, subject, requestId);
            // ── Downstream call stub (replace with real WebClient proxy) ──────
            // In production this would be:
            //   webClient.method(request.method())
            //       .uri(downstreamBaseUrl + path)
            //       .header(DOWNSTREAM_SUBJECT_HEADER, subject)
            //       .header(RequestIdFilter.REQUEST_ID_HEADER, requestId)
            //       .retrieve()
            //       .bodyToMono(String.class)
            //       .transformDeferred(CircuitBreakerOperator.of(circuitBreaker))
            //       .onErrorResume(ex -> fallbackResponse(request, ex));
            Mono<ServerResponse> downstreamCall = buildStubResponse(
                    path, method, subject, requestId);
            // Apply circuit breaker — when open, errors trigger fallback.
            return downstreamCall
                    .transformDeferred(CircuitBreakerOperator.of(circuitBreaker))
                    .onErrorResume(ex -> {
                        log.warn("Circuit breaker triggered — redirecting to fallback. "
                                        + "path={} subject={} requestId={} error={}",
                                path, subject, requestId, ex.getMessage());
                        return redirectToFallback(request, path, requestId);
                    });
        });
    }
    /**
     * Catch-all handler for routes that do not match any registered pattern.
     * Returns {@code 404 Not Found} with an RFC 7807 Problem+JSON body.
     */
    private Mono<ServerResponse> handleNotFound(ServerRequest request) {
        return Mono.deferContextual(ctx -> {
            String requestId = ctx.getOrDefault(
                    RequestIdFilter.REQUEST_ID_CONTEXT_KEY, "none");
            String path = request.path();
            log.info("Handling not found request — path={} method={} requestId={}", path, request.method().name(), requestId);
            log.warn("No route matched — path={} method={} requestId={}",
                    path, request.method().name(), requestId);
            String body = String.format("""
                    {
                      "type":      "https://httpstatuses.com/404",
                      "title":     "Not Found",
                      "status":    404,
                      "detail":    "No route found for path '%s'.",
                      "requestId": "%s"
                    }
                    """, path, requestId);
            return ServerResponse
                    .status(HttpStatus.NOT_FOUND)
                    .contentType(MediaType.APPLICATION_PROBLEM_JSON)
                    .bodyValue(body);
        });
    }
    // ─────────────────────────────────────────────────────────────────────────
    // Circuit breaker
    // ─────────────────────────────────────────────────────────────────────────
    /**
     * Builds and registers the Resilience4j circuit breaker that protects
     * downstream API calls.
     *
     * <p>Configuration:
     * <ul>
     *   <li>Opens after 50% failure rate in a 10-call sliding window.</li>
     *   <li>Stays open for 30 seconds before entering HALF_OPEN state.</li>
     *   <li>Allows 5 test calls in HALF_OPEN before deciding to close or re-open.</li>
     *   <li>Counts calls slower than 2 seconds as failures (slow-call threshold).</li>
     * </ul>
     *
     * @param registry the Resilience4j registry — auto-configured by the starter
     * @return a fully configured {@link CircuitBreaker}
     */
    private CircuitBreaker buildDownstreamCircuitBreaker(CircuitBreakerRegistry registry) {
        log.info("Building downstream circuit breaker");
        CircuitBreakerConfig config = CircuitBreakerConfig.custom()
                .slidingWindowType(CircuitBreakerConfig.SlidingWindowType.COUNT_BASED)
                .slidingWindowSize(10)
                .failureRateThreshold(50.0f)
                .slowCallRateThreshold(50.0f)
                .slowCallDurationThreshold(Duration.ofSeconds(2))
                .waitDurationInOpenState(Duration.ofSeconds(30))
                .permittedNumberOfCallsInHalfOpenState(5)
                .automaticTransitionFromOpenToHalfOpenEnabled(true)
                .recordExceptions(Exception.class)
                .build();
        CircuitBreaker cb = registry.circuitBreaker(DOWNSTREAM_CB_NAME, config);
        // Attach event listeners for observability
        cb.getEventPublisher()
                .onStateTransition(event ->
                        log.info("Circuit breaker '{}' state transition: {} → {}",
                                DOWNSTREAM_CB_NAME,
                                event.getStateTransition().getFromState(),
                                event.getStateTransition().getToState()))
                .onError(event ->
                        log.error("Circuit breaker '{}' recorded error: {}",
                                DOWNSTREAM_CB_NAME, event.getThrowable().getMessage()))
                .onSlowCallRateExceeded(event ->
                        log.warn("Circuit breaker '{}' slow-call rate exceeded: {}%",
                                DOWNSTREAM_CB_NAME, event.getSlowCallRate()));
        return cb;
    }
    // ─────────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────────
    /**
     * Resolves the authenticated subject from the Reactor Context.
     *
     * <p>The {@link JWTClaimsSet} is placed in the context by
     * {@link JwtVerificationFilter} after successful JWT verification.
     *
     * @param ctx the Reactor ContextView from the current subscription
     * @return the {@code sub} claim, or {@code "anonymous"} if not present
     */
    private String resolveSubject(reactor.util.context.ContextView ctx) {
        try {
            JWTClaimsSet claims = ctx.getOrDefault(
                    JwtVerificationFilter.CLAIMS_CONTEXT_KEY, null);
            if (claims == null) {
                return "anonymous";
            }
            String sub = claims.getSubject();
            return sub != null ? sub : "<no-sub>";
        } catch (Exception ex) {
            log.warn("Could not resolve subject from claims context: {}", ex.getMessage());
            return "<unknown>";
        }
    }
    /**
     * Builds a stub downstream response for demonstration purposes.
     *
     * <p><strong>Replace this method</strong> with a real
     * {@link org.springframework.web.reactive.function.client.WebClient}
     * proxy call to the target microservice in production.
     *
     * @param path      the requested API path
     * @param method    the HTTP method
     * @param subject   the authenticated subject forwarded from JWT claims
     * @param requestId the correlation request ID
     * @return a {@link Mono} emitting a stub {@link ServerResponse}
     */
    private Mono<ServerResponse> buildStubResponse(
            String path,
            String method,
            String subject,
            String requestId) {
        log.info("Building stub response for path={} method={}", path, method);
        String body = String.format("""
                {
                  "path":      "%s",
                  "method":    "%s",
                  "subject":   "%s",
                  "requestId": "%s",
                  "timestamp": "%s",
                  "message":   "API request processed successfully. Replace this stub with a real downstream WebClient call."
                }
                """, path, method, subject, requestId, Instant.now());
        return ServerResponse.ok()
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body);
    }
    /**
     * Redirects the client to the fallback endpoint when the circuit breaker
     * is open or the downstream call fails.
     *
     * <p>Uses an HTTP {@code 307 Temporary Redirect} to the {@code /fallback}
     * path mirroring the original API path (e.g. {@code /api/orders} →
     * {@code /fallback/api/orders}).  This allows the fallback handler to
     * log which downstream route triggered the fallback.
     *
     * @param request   the original API request
     * @param path      the original API path
     * @param requestId the correlation request ID
     * @return a {@code 307} redirect response to the fallback endpoint
     */
    private Mono<ServerResponse> redirectToFallback(
            ServerRequest request,
            String path,
            String requestId) {
        String fallbackPath = "/fallback" + path;
        log.info("Redirecting to fallback — originalPath={} fallbackPath={} requestId={}",
                path, fallbackPath, requestId);
        return ServerResponse
                .temporaryRedirect(URI.create(fallbackPath))
                .build();
    }

}