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
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;
import reactor.util.context.ContextView;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;

import static org.springframework.web.reactive.function.server.RequestPredicates.*;

/**
 * RouteConfig
 *
 * Functional-style API Gateway routing using WebClient + RouterFunction.
 *
 * Architecture:
 *   Client → Gateway (10008) → Eureka/Consul → doc-service (10005)
 *
 * Path forwarding:
 *   Gateway receives:  POST /doc-service/pdf/unlock
 *   Resolved target:   http://<doc-service-ip>:10005/doc-service/pdf/unlock
 *   (full path preserved — doc-service runs with context-path=/doc-service)
 *
 * Adding a new downstream service:
 *   1. Add its lb:// constant below (SERVICE REGISTRY section)
 *   2. Add its routes in gatewayRouterFunction() (ROUTES section)
 *   That's it — circuit breaker, JWT propagation, logging are all automatic.
 */
@Configuration
public class RouteConfig {

    private static final Logger log = LoggerFactory.getLogger(RouteConfig.class);

    // ── Headers ───────────────────────────────────────────────────────────────

    private static final String HEADER_SUBJECT    = "X-Authenticated-Subject";
    private static final String HEADER_REQUEST_ID = RequestIdFilter.REQUEST_ID_HEADER;

    /**
     * Headers that must never be forwarded to downstream services.
     * Authorization is stripped — downstream services trust X-Authenticated-Subject
     * which is set by this gateway after JWT verification.
     */
    private static final Set<String> BLOCKED_HEADERS = Set.of(
            "authorization",
            "cookie",
            "set-cookie",
            "host",
            "connection",
            "transfer-encoding"
    );

    // ── Service Registry ──────────────────────────────────────────────────────
    // lb:// prefix → Spring Cloud LoadBalancer resolves via Eureka/Consul.
    // Value must match spring.application.name of the target service.

    private static final String DOC_SERVICE = "lb://doc-service";

    // Add more services here as your system grows:
    // private static final String USER_SERVICE    = "lb://user-service";
    // private static final String PAYMENT_SERVICE = "lb://payment-service";

    // ── Circuit Breaker ───────────────────────────────────────────────────────

    private static final String CB_NAME = "downstreamService";

    // ─────────────────────────────────────────────────────────────────────────
    // Beans
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Load-balanced WebClient shared across all proxy calls.
     * ReactorLoadBalancerExchangeFilterFunction resolves lb:// URIs via the registry.
     */
    @Bean
    public WebClient lbWebClient(
            WebClient.Builder builder,
            org.springframework.cloud.client.loadbalancer.reactive.ReactorLoadBalancerExchangeFilterFunction lbFunction) {
        return builder
                .filter(lbFunction)
                .build();
    }

    /**
     * All gateway routes.
     *
     * Matching order (first match wins — order matters):
     *   1. Internal routes  → /health, /fallback/**, /public/**
     *   2. Service routes   → /doc-service/**, /user-service/**, ...
     *   3. Catch-all        → 404
     */
    @Bean
    public RouterFunction<ServerResponse> gatewayRouterFunction(
            WebClient lbWebClient,
            CircuitBreakerRegistry cbRegistry) {

        CircuitBreaker cb = buildCircuitBreaker(cbRegistry);

        return RouterFunctions

                // ── Internal routes (no JWT, no proxy) ───────────────────────
                .route(GET("/health"),          req -> handleHealth(req))
                .andRoute(GET("/fallback/**"),  req -> handleFallback(req))
                .andRoute(GET("/public/**"),    req -> handlePublic(req))

                // ── doc-service routes ────────────────────────────────────────
                // One wildcard per HTTP method covers every endpoint in HomeController.
                // context-path /doc-service is preserved — no path rewriting needed.
                .andRoute(GET("/doc-service/**"),
                        req -> proxy(req, DOC_SERVICE, lbWebClient, cb))
                .andRoute(POST("/doc-service/**"),
                        req -> proxy(req, DOC_SERVICE, lbWebClient, cb))
                .andRoute(PUT("/doc-service/**"),
                        req -> proxy(req, DOC_SERVICE, lbWebClient, cb))
                .andRoute(DELETE("/doc-service/**"),
                        req -> proxy(req, DOC_SERVICE, lbWebClient, cb))

                // ── Add new services here ─────────────────────────────────────
                // .andRoute(GET("/user-service/**"),
                //         req -> proxy(req, USER_SERVICE, lbWebClient, cb))
                // .andRoute(POST("/user-service/**"),
                //         req -> proxy(req, USER_SERVICE, lbWebClient, cb))

                // ── Catch-all 404 ─────────────────────────────────────────────
                .andRoute(req -> true, req -> handleNotFound(req));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Core Proxy
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Proxies the incoming request to the downstream service.
     *
     * Steps:
     *   1. Read requestId + authenticated subject from Reactor Context
     *   2. Build target URL: serviceBase + fullPath + queryString
     *   3. Forward safe headers + inject X-Authenticated-Subject, X-Request-ID
     *   4. Stream request body (for POST/PUT/PATCH) or send bodyless (GET/DELETE)
     *   5. Map downstream response status + body back to the caller
     *   6. Apply circuit breaker
     *   7. On 4xx/5xx → return downstream error as-is (not a fallback)
     *   8. On network/CB failure → redirect to /fallback/<path>
     */
    private Mono<ServerResponse> proxy(
            ServerRequest request,
            String serviceBase,
            WebClient webClient,
            CircuitBreaker circuitBreaker) {

        return Mono.deferContextual(ctx -> {

            String requestId = resolveRequestId(ctx);
            String subject   = resolveSubject(ctx);
            String path      = request.uri().getRawPath();
            String query     = request.uri().getRawQuery();
            String targetUrl = serviceBase + path + (query != null ? "?" + query : "");

            log.info("PROXY method={} path={} target={} subject={} requestId={}",
                    request.method(), path, targetUrl, subject, requestId);

            // Build the outgoing request
            WebClient.RequestBodySpec outbound = webClient
                    .method(request.method())
                    .uri(targetUrl)
                    .header(HEADER_SUBJECT,    subject)
                    .header(HEADER_REQUEST_ID, requestId)
                    .headers(h -> request.headers().asHttpHeaders().forEach((name, values) -> {
                        if (isSafeHeader(name)) {
                            h.put(name, values);
                        }
                    }));

            // Attach body for write methods; leave bodyless for read methods
            Mono<ServerResponse> downstream = isReadMethod(request.method())
                    ? sendBodyless(outbound)
                    : sendWithBody(outbound, request);

            return downstream
                    .transformDeferred(CircuitBreakerOperator.of(circuitBreaker))
                    .onErrorResume(DownstreamClientException.class, ex -> {
                        // 4xx/5xx from downstream — return it directly to the caller
                        log.warn("Downstream error status={} path={} requestId={}",
                                ex.statusCode, path, requestId);
                        return ServerResponse
                                .status(ex.statusCode)
                                .contentType(MediaType.APPLICATION_PROBLEM_JSON)
                                .bodyValue(ex.body != null ? ex.body : "");
                    })
                    .onErrorResume(ex -> {
                        // Network failure, timeout, circuit breaker open
                        log.error("Proxy failure path={} error={} requestId={}",
                                path, ex.getMessage(), requestId, ex);
                        return redirectToFallback(path);
                    });
        });
    }

    /**
     * Sends a GET / DELETE / HEAD request (no body).
     */
    private Mono<ServerResponse> sendBodyless(WebClient.RequestBodySpec spec) {
        return spec
                .retrieve()
                .onStatus(
                        status -> status.is4xxClientError() || status.is5xxServerError(),
                        response -> response.bodyToMono(String.class)
                                .flatMap(body -> Mono.error(
                                        new DownstreamClientException(
                                                response.statusCode().value(), body)))
                )
                .toEntityFlux(byte[].class)
                .flatMap(entity -> {
                    ServerResponse.BodyBuilder builder =
                            ServerResponse.status(entity.getStatusCode());

                    if (entity.getHeaders().getContentType() != null) {
                        builder.contentType(entity.getHeaders().getContentType());
                    }

                    return entity.getBody() != null
                            ? builder.body(entity.getBody(), byte[].class)
                            : builder.build();
                });
    }

    /**
     * Sends a POST / PUT / PATCH request — streams the request body through.
     * Uses byte[] to handle any content type: JSON, multipart, PDF, ZIP, etc.
     */
    private Mono<ServerResponse> sendWithBody(
            WebClient.RequestBodySpec spec,
            ServerRequest request) {

        return spec
                .contentType(request.headers().contentType()
                        .orElse(MediaType.APPLICATION_OCTET_STREAM))
                .body(BodyInserters.fromDataBuffers(request.exchange().getRequest().getBody()))
                .retrieve()
                .onStatus(
                        status -> status.is4xxClientError() || status.is5xxServerError(),
                        response -> response.bodyToMono(String.class)
                                .flatMap(body -> Mono.error(
                                        new DownstreamClientException(
                                                response.statusCode().value(), body)))
                )
                .toEntityFlux(byte[].class)
                .flatMap(entity -> {
                    ServerResponse.BodyBuilder builder =
                            ServerResponse.status(entity.getStatusCode());

                    if (entity.getHeaders().getContentType() != null) {
                        builder.contentType(entity.getHeaders().getContentType());
                    }

                    // Forward custom response headers from downstream (Content-Disposition,
                    // X-Compression-Ratio, X-Merged-Files-Count, etc.)
                    entity.getHeaders().forEach((name, values) -> {
                        if (isForwardableResponseHeader(name)) {
                            builder.header(name, values.toArray(new String[0]));
                        }
                    });

                    return entity.getBody() != null
                            ? builder.body(entity.getBody(), byte[].class)
                            : builder.build();
                });
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Internal Route Handlers
    // ─────────────────────────────────────────────────────────────────────────

    private Mono<ServerResponse> handleHealth(ServerRequest request) {
        String requestId = resolveRequestIdFromRequest(request);
        String body = """
                {
                  "status":    "UP",
                  "service":   "api-gateway",
                  "timestamp": "%s",
                  "requestId": "%s"
                }
                """.formatted(Instant.now(), requestId);
        return ServerResponse.ok()
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body);
    }

    private Mono<ServerResponse> handleFallback(ServerRequest request) {
        String requestId   = resolveRequestIdFromRequest(request);
        String triggeredBy = request.path().replaceFirst("^/fallback", "");
        log.warn("Fallback triggered path={} requestId={}", triggeredBy, requestId);
        String body = """
                {
                  "type":        "https://httpstatuses.com/503",
                  "title":       "Service Unavailable",
                  "status":      503,
                  "detail":      "The requested service is temporarily unavailable. Please retry shortly.",
                  "triggeredBy": "%s",
                  "requestId":   "%s"
                }
                """.formatted(triggeredBy, requestId);
        return ServerResponse.status(HttpStatus.SERVICE_UNAVAILABLE)
                .contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .bodyValue(body);
    }

    private Mono<ServerResponse> handlePublic(ServerRequest request) {
        String requestId = resolveRequestIdFromRequest(request);
        String body = """
                {
                  "path":      "%s",
                  "requestId": "%s",
                  "message":   "Public resource."
                }
                """.formatted(request.path(), requestId);
        return ServerResponse.ok()
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body);
    }

    private Mono<ServerResponse> handleNotFound(ServerRequest request) {
        String requestId = resolveRequestIdFromRequest(request);
        log.warn("No route matched path={} method={} requestId={}",
                request.path(), request.method(), requestId);
        String body = """
                {
                  "type":      "https://httpstatuses.com/404",
                  "title":     "Not Found",
                  "status":    404,
                  "detail":    "No route found for '%s'.",
                  "requestId": "%s"
                }
                """.formatted(request.path(), requestId);
        return ServerResponse.status(HttpStatus.NOT_FOUND)
                .contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .bodyValue(body);
    }

    private Mono<ServerResponse> redirectToFallback(String originalPath) {
        String fallbackPath = "/fallback" + originalPath;
        log.info("Redirecting to fallback path={}", fallbackPath);
        return ServerResponse.temporaryRedirect(URI.create(fallbackPath)).build();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Circuit Breaker
    // ─────────────────────────────────────────────────────────────────────────

    private CircuitBreaker buildCircuitBreaker(CircuitBreakerRegistry registry) {

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

        CircuitBreaker cb = registry.circuitBreaker(CB_NAME, config);

        cb.getEventPublisher()
                .onStateTransition(e -> log.warn(
                        "CB state transition {} → {}",
                        e.getStateTransition().getFromState(),
                        e.getStateTransition().getToState()))
                .onError(e -> log.error(
                        "CB recorded error: {}",
                        e.getThrowable().getMessage()))
                .onSlowCallRateExceeded(e -> log.warn(
                        "CB slow-call rate exceeded: {}%",
                        e.getSlowCallRate()));

        return cb;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────────

    private boolean isReadMethod(HttpMethod method) {
        return method == HttpMethod.GET
                || method == HttpMethod.DELETE
                || method == HttpMethod.HEAD;
    }

    /**
     * Headers safe to forward to downstream services.
     * Uses a blocklist — anything not explicitly blocked is forwarded.
     */
    private boolean isSafeHeader(String name) {
        return name != null && !BLOCKED_HEADERS.contains(name.toLowerCase());
    }

    /**
     * Response headers from downstream that should be passed back to the caller.
     * Includes Content-Disposition and all custom X- headers set by doc-service.
     */
    private boolean isForwardableResponseHeader(String name) {
        if (name == null) return false;
        String lower = name.toLowerCase();
        return lower.equals("content-disposition")
                || lower.startsWith("x-");
    }

    private String resolveRequestId(ContextView ctx) {
        return ctx.getOrDefault(RequestIdFilter.REQUEST_ID_CONTEXT_KEY, "none");
    }

    /**
     * Reads requestId directly from the incoming request header
     * (used in internal handlers that run outside deferContextual).
     */
    private String resolveRequestIdFromRequest(ServerRequest request) {
        return request.headers().firstHeader(HEADER_REQUEST_ID) != null
                ? request.headers().firstHeader(HEADER_REQUEST_ID)
                : "none";
    }

    /**
     * Reads the authenticated subject from the Reactor Context.
     * Set by JwtVerificationFilter after token validation.
     * Returns "anonymous" for public/unprotected paths.
     */
    private String resolveSubject(ContextView ctx) {
        try {
            JWTClaimsSet claims = ctx.getOrDefault(
                    JwtVerificationFilter.CLAIMS_CONTEXT_KEY, null);
            if (claims == null) return "anonymous";
            String sub = claims.getSubject();
            return sub != null ? sub : "<no-sub>";
        } catch (Exception ex) {
            log.warn("Could not resolve subject from JWT claims: {}", ex.getMessage());
            return "<unknown>";
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Exceptions
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Wraps a 4xx or 5xx response from a downstream service.
     * Caught in the proxy layer and returned directly to the caller —
     * these are NOT circuit-breaker failures and do NOT trigger the fallback.
     */
    private static final class DownstreamClientException extends RuntimeException {
        final int    statusCode;
        final String body;

        DownstreamClientException(int statusCode, String body) {
            super("Downstream returned HTTP " + statusCode);
            this.statusCode = statusCode;
            this.body       = body;
        }
    }
}