package in.guardianservices.api_gateway.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.util.context.Context;
import java.util.UUID;
/**
 * First filter in the gateway chain ({@code @Order(1)}).
 *
 * <p>Responsible for assigning a unique {@code X-Request-ID} to every inbound
 * HTTP request and propagating it through the entire reactive pipeline so that
 * every log line for a given request can be correlated by that ID.
 *
 * <h3>Problem with the original implementation</h3>
 * The original code used SLF4J's {@code MDC} (Mapped Diagnostic Context):
 * <pre>{@code
 *   MDC.put("requestId", requestId);
 *   return chain.filter(exchange).doFinally(s -> MDC.remove("requestId"));
 * }</pre>
 * {@code MDC} is <strong>thread-local</strong>.  In a Project Reactor / WebFlux
 * pipeline a single request routinely hops across multiple threads (Netty I/O
 * thread → bounded-elastic scheduler → back).  The {@code MDC} value set on
 * thread A is invisible on thread B, so log lines emitted on thread B carry no
 * {@code requestId}.  Under load, MDC values also leak across requests when
 * thread-pool threads are reused before {@code doFinally} executes.
 *
 * <h3>Solution: Reactor Context</h3>
 * Reactor's {@link Context} is an immutable, per-subscription key-value store
 * that travels with the reactive pipeline regardless of thread switches.  This
 * filter:
 * <ol>
 *   <li>Determines the request ID (from the incoming header or generates a UUID).</li>
 *   <li>Mutates the request and response to carry the ID as a header so
 *       downstream services and clients can correlate traces.</li>
 *   <li>Writes the ID into the Reactor {@link Context} via
 *       same subscription can read it with
 *       {@link Mono#deferContextual(java.util.function.Function)}.</li>
 * </ol>
 *
 * <h3>Logging with Reactor Context</h3>
 * To include {@code requestId} in log lines from any operator downstream, use:
 * <pre>{@code
 *   Mono.deferContextual(ctx -> {
 *       String id = ctx.getOrDefault(RequestIdFilter.REQUEST_ID_CONTEXT_KEY, "none");
 *       log.info("Processing — requestId={}", id);
 *       return Mono.just(...);
 *   });
 * }</pre>
 * Alternatively, configure
 * <a href="https://github.com/reactor/reactor-core/tree/main/reactor-core-micrometer">
 * reactor-core-micrometer</a> with the Logback MDC adapter to bridge the
 * Reactor Context into MDC automatically for all log statements.
 *
 * <h3>Security considerations</h3>
 * <ul>
 *   <li>The incoming {@code X-Request-ID} header is accepted only if it is a
 *       valid UUID string.  Any other value (including potential injection
 *       payloads) is silently replaced with a server-generated UUID.</li>
 *   <li>The validated/generated ID is echoed back in the response
 *       {@code X-Request-ID} header so clients can correlate their own logs.</li>
 * </ul>
 */
@Component
@Order(1)
public class RequestIdFilter implements WebFilter {

    private static final Logger log = LoggerFactory.getLogger(RequestIdFilter.class);

    /** HTTP request/response header name carrying the request correlation ID. */
    public static final String REQUEST_ID_HEADER = "X-Request-ID";

    /**
     * Key used to store the request ID in the Reactor {@link Context}.
     * Downstream operators retrieve it via:
     * <pre>{@code ctx.getOrDefault(RequestIdFilter.REQUEST_ID_CONTEXT_KEY, "none")}</pre>
     */
    public static final String REQUEST_ID_CONTEXT_KEY = "requestId";

    /**
     * Maximum length accepted for a client-supplied {@code X-Request-ID}.
     * Prevents oversized header values from reaching the Reactor Context.
     */
    private static final int MAX_REQUEST_ID_LENGTH = 64;

    // ─────────────────────────────────────────────────────────────────────────
    // WebFilter
    // ─────────────────────────────────────────────────────────────────────────
    /**
     * Assigns a {@code requestId} to the exchange and propagates it via:
     * <ol>
     *   <li>A mutated {@code X-Request-ID} request header (visible to downstream handlers).</li>
     *   <li>The {@code X-Request-ID} response header (visible to callers for correlation).</li>
     *   <li>The Reactor {@link Context} (readable by every downstream operator).</li>
     * </ol>
     */
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        log.info("Processing request in RequestIdFilter");
        String requestId = resolveRequestId(exchange.getRequest());
        // Mutate request — add/overwrite the header so downstream handlers
        // (e.g. service route handlers) can read it from the request object.
        ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                .header(REQUEST_ID_HEADER, requestId)
                .build();
        // Mutate response — echo the ID back to the caller so they can
        // correlate their client-side logs with gateway/backend logs.
        ServerHttpResponse mutatedResponse = exchange.getResponse();
        mutatedResponse.getHeaders().set(REQUEST_ID_HEADER, requestId);
        ServerWebExchange mutatedExchange = exchange.mutate()
                .request(mutatedRequest)
                .build();
        log.info("Assigned requestId={} to request with method={} and path={}",
                requestId,
                exchange.getRequest().getMethod(),
                exchange.getRequest().getURI().getPath());
        log.debug("Request assigned requestId={} method={} path={}",
                requestId,
                exchange.getRequest().getMethod(),
                exchange.getRequest().getURI().getPath());
        // contextWrite() attaches the requestId to the Reactor Context for the
        // entire downstream pipeline.  It is called AFTER chain.filter() because
        // contextWrite propagates *upstream* in the operator chain — Reactor
        // evaluates context writes from bottom to top.
        return chain.filter(mutatedExchange)
                .contextWrite(Context.of(REQUEST_ID_CONTEXT_KEY, requestId));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────────
    /**
     * Determines the request ID for this exchange using the following strategy:
     * <ol>
     *   <li>Read the incoming {@code X-Request-ID} header.</li>
     *   <li>If present, validate it is a well-formed UUID (prevents header
     *       injection and enforces a canonical format).</li>
     *   <li>If absent or invalid, generate a fresh random UUID.</li>
     * </ol>
     *
     * @param request the incoming server HTTP request
     * @return a non-null, non-blank request ID string
     */
    private String resolveRequestId(ServerHttpRequest request) {
        String incoming = request.getHeaders().getFirst(REQUEST_ID_HEADER);
        if (incoming != null
                && !incoming.isBlank()
                && incoming.length() <= MAX_REQUEST_ID_LENGTH
                && isValidUuid(incoming)) {
            log.info("Reusing client-supplied X-Request-ID={}", incoming);
            log.trace("Reusing client-supplied X-Request-ID={}", incoming);
            return incoming;
        }
        if (incoming != null && !incoming.isBlank()) {
            // Client sent something, but it was not a valid UUID.
            log.info("Ignoring invalid client-supplied X-Request-ID='{}' and generating a new one", sanitise(incoming));
            log.debug("Ignoring invalid client-supplied X-Request-ID='{}' — generating new ID",
                    sanitise(incoming));
        }
        String newRequestId = UUID.randomUUID().toString();
        log.info("Generated new X-Request-ID={}", newRequestId);
        return newRequestId;
    }

    /**
     * Returns {@code true} if the given string is a syntactically valid UUID.
     * Uses {@link UUID#fromString(String)} which performs a strict format check.
     *
     * @param value the string to test
     * @return {@code true} if {@code value} is a valid UUID
     */
    private boolean isValidUuid(String value) {
        try {
            UUID.fromString(value);
            return true;
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }

    /**
     * Truncates and strips non-printable characters from an untrusted header
     * value before including it in a log statement.
     * Prevents log injection attacks (CWE-117).
     *
     * @param raw the raw, potentially malicious header value
     * @return a safe, printable representation for logging
     */
    private String sanitise(String raw) {
        if (raw == null) {
            return "<null>";
        }
        // Remove newlines, carriage returns, and other control characters,
        // then truncate to a safe display length.
        return raw.replaceAll("[\\r\\n\\t]", "_")
                .substring(0, Math.min(raw.length(), 40));
    }
}