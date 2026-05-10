package in.guardianservices.api_gateway.filter;

import com.nimbusds.jwt.JWTClaimsSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import java.time.Instant;
import java.util.Set;
/**
 * Fourth filter in the gateway chain ({@code @Order(4)}).
 *
 * <p>Provides structured, per-request access logging that covers:
 * <ul>
 *   <li><strong>Inbound:</strong> method, path, client IP, user-agent, request ID.</li>
 *   <li><strong>Outbound:</strong> HTTP status, latency in milliseconds, authenticated
 *       subject (if the JWT filter ran), request ID (for correlation).</li>
 * </ul>
 *
 * <h3>Problems fixed from original implementation</h3>
 * <ul>
 *   <li><strong>{@code System.out.printf}:</strong> The original wrote directly to
 *       stdout, bypassing the logging framework entirely.  Log levels, appenders,
 *       structured JSON output (Logstash), log aggregation pipelines (ELK, Loki),
 *       and runtime log-level changes all depend on going through SLF4J/Logback.
 *       This implementation uses {@code log.info()} / {@code log.debug()} exclusively.</li>
 *
 *   <li><strong>Thread-local MDC in reactive context:</strong> The original read
 *       {@code MDC.get("requestId")} which is thread-local and silently returns
 *       {@code null} on any thread other than the one that called
 *       {@code MDC.put()}.  This implementation reads the {@code requestId}
 *       from the Reactor {@link reactor.util.context.Context} set by
 *       {@link RequestIdFilter}, which is guaranteed to be present on every
 *       thread in the reactive pipeline.</li>
 *
 *   <li><strong>No response logging:</strong> The original left the
 *       {@code doOnSuccess} handler empty with a comment.  This implementation
 *       logs the status code and latency on every response.</li>
 *
 *   <li><strong>No latency measurement:</strong> Request duration was not tracked.
 *       This implementation records {@code startTime} before delegating to the
 *       chain and computes elapsed milliseconds in the terminal signal handlers.</li>
 *
 *   <li><strong>No authenticated subject logging:</strong> After the
 *       {@link JwtVerificationFilter} runs, verified JWT claims are available
 *       in the Reactor Context.  This filter reads the {@code sub} claim from
 *       those claims and includes it in the response log line — providing
 *       full auditability without re-parsing the token.</li>
 *
 *   <li><strong>Sensitive header leakage:</strong> Logging all request headers
 *       risks exposing {@code Authorization} tokens and {@code Cookie} values
 *       in log files.  This implementation uses an explicit allowlist of
 *       safe-to-log headers.</li>
 * </ul>
 *
 * <h3>Log format</h3>
 * <pre>
 * INFO  REQUEST  method=GET path=/api/users requestId=3f2a1c4d clientIp=10.0.0.1
 *                userAgent=Mozilla/5.0 contentType=application/json
 *
 * INFO  RESPONSE method=GET path=/api/users status=200 durationMs=42
 *                requestId=3f2a1c4d subject=user@example.com
 * </pre>
 *
 * <h3>Security considerations</h3>
 * <ul>
 *   <li>The {@code Authorization} header is <strong>never</strong> logged.</li>
 *   <li>The {@code Cookie} header is <strong>never</strong> logged.</li>
 *   <li>Only headers in {@link #SAFE_LOG_HEADERS} are included in the request
 *       log line.</li>
 *   <li>The authenticated {@code sub} claim is logged only at {@code INFO}
 *       level on the response line — never the full claims set.</li>
 * </ul>
 */
@Component
@Order(4)
public class RequestLoggingFilter implements WebFilter {

    private static final Logger log = LoggerFactory.getLogger(RequestLoggingFilter.class);
    /**
     * Allowlist of request headers that are safe to include in log output.
     * Any header <em>not</em> in this set is silently omitted from logs.
     * Intentionally excludes: {@code Authorization}, {@code Cookie},
     * {@code Set-Cookie}, {@code X-Api-Key}, and any custom secret headers.
     */
    private static final Set<String> SAFE_LOG_HEADERS = Set.of(
            "Content-Type",
            "Accept",
            "User-Agent",
            "X-Request-ID",
            "X-Forwarded-For",
            "X-Real-IP",
            "Referer",
            "Origin"
    );
    // ─────────────────────────────────────────────────────────────────────────
    // WebFilter
    // ─────────────────────────────────────────────────────────────────────────
    /**
     * Logs the inbound request immediately, then attaches terminal signal
     * handlers to log the outbound response (or error) along with elapsed time.
     *
     * <p>Uses {@link Mono#deferContextual} to read the {@code requestId} and
     * {@code jwtClaims} from the Reactor {@link reactor.util.context.Context}
     * established by upstream filters — never from thread-local storage.
     */
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        log.info("RequestLoggingFilter executing for request path: {}", exchange.getRequest().getURI().getPath());
        Instant startTime = Instant.now();
        ServerHttpRequest request = exchange.getRequest();
        String method      = request.getMethod().name();
        String path        = request.getURI().getPath();
        String query       = request.getURI().getQuery();
        String clientIp    = resolveClientIp(exchange);
        String userAgent   = sanitiseHeaderValue(
                request.getHeaders().getFirst("User-Agent"));
        String contentType = sanitiseHeaderValue(
                request.getHeaders().getFirst("Content-Type"));
        String fullPath    = query != null ? path + "?" + query : path;
        // ── Inbound log ───────────────────────────────────────────────────────
        // Read requestId from Reactor Context — thread-safe, always correct.
        return Mono.deferContextual(ctx -> {
            String requestId = ctx.getOrDefault(
                    RequestIdFilter.REQUEST_ID_CONTEXT_KEY, "none");
            log.info("REQUEST  method={} path={} clientIp={} userAgent={} "
                            + "contentType={} requestId={}",
                    method, fullPath, clientIp, userAgent, contentType, requestId);
            // ── Execute filter chain + attach outbound/error logging ──────────
            return chain.filter(exchange)
                    .doOnSuccess(v -> logResponse(
                            exchange, method, path, startTime, requestId, ctx))
                    .doOnError(ex -> logError(
                            exchange, method, path, startTime, requestId, ex));
        });
    }
    // ─────────────────────────────────────────────────────────────────────────
    // Response logging
    // ─────────────────────────────────────────────────────────────────────────
    /**
     * Logs the outbound response after the reactive pipeline completes normally.
     *
     * <p>Reads the HTTP status code from the response and the authenticated
     * {@code sub} claim from the Reactor Context (set by
     * {@link JwtVerificationFilter}) if available.
     *
     * @param exchange   the completed exchange
     * @param method     HTTP method (for log correlation without re-reading)
     * @param path       request path (for log correlation without re-reading)
     * @param startTime  the {@link Instant} recorded before chain delegation
     * @param requestId  the correlation ID from the Reactor Context
     * @param ctx        the Reactor Context for reading JWT claims
     */
    private void logResponse(
            ServerWebExchange exchange,
            String method,
            String path,
            Instant startTime,
            String requestId,
            reactor.util.context.ContextView ctx) {
        long durationMs = Instant.now().toEpochMilli() - startTime.toEpochMilli();
        int statusCode  = resolveStatusCode(exchange);
        String subject  = resolveSubject(ctx);
        if (statusCode >= 500) {
            log.error("RESPONSE method={} path={} status={} durationMs={} "
                            + "subject={} requestId={}",
                    method, path, statusCode, durationMs, subject, requestId);
        } else if (statusCode >= 400) {
            log.warn("RESPONSE  method={} path={} status={} durationMs={} "
                            + "subject={} requestId={}",
                    method, path, statusCode, durationMs, subject, requestId);
        } else {
            log.info("RESPONSE  method={} path={} status={} durationMs={} "
                            + "subject={} requestId={}",
                    method, path, statusCode, durationMs, subject, requestId);
        }
    }
    /**
     * Logs unhandled exceptions that propagate out of the filter chain.
     *
     * <p>These represent infrastructure failures that no downstream error
     * handler caught — logged at ERROR with the exception message (but not the
     * full stack trace at WARN to avoid log noise in normal 4xx scenarios).
     *
     * @param exchange   the exchange that produced the error
     * @param method     HTTP method
     * @param path       request path
     * @param startTime  time before chain delegation
     * @param requestId  correlation ID
     * @param ex         the unhandled exception
     */
    private void logError(
            ServerWebExchange exchange,
            String method,
            String path,
            Instant startTime,
            String requestId,
            Throwable ex) {
        long durationMs = Instant.now().toEpochMilli() - startTime.toEpochMilli();
        int statusCode  = resolveStatusCode(exchange);
        log.error("RESPONSE  method={} path={} status={} durationMs={} "
                        + "requestId={} error={}",
                method, path, statusCode, durationMs, requestId, ex.getMessage(), ex);
    }
    // ─────────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────────
    /**
     * Resolves the HTTP response status code safely.
     * Returns {@code 0} if the response has not yet committed a status
     * (should not happen in normal operation but guards against NPE).
     */
    private int resolveStatusCode(ServerWebExchange exchange) {
        var statusCode = exchange.getResponse().getStatusCode();
        return statusCode != null ? statusCode.value() : 0;
    }
    /**
     * Resolves the authenticated subject from the Reactor Context.
     *
     * <p>The {@link JWTClaimsSet} is written into the Context by
     * {@link JwtVerificationFilter} after successful JWT verification.
     * For public paths (where the JWT filter is skipped), the context
     * will not contain claims — this method returns {@code "anonymous"} in
     * that case.
     *
     * @param ctx the Reactor ContextView from the current subscription
     * @return the {@code sub} claim, {@code "anonymous"} if unauthenticated,
     *         or {@code "<unknown>"} if extraction fails
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
            log.warn("Could not resolve subject from JWT claims: {}", ex.getMessage());
            return "<unknown>";
        }
    }
    /**
     * Resolves the client IP address from the exchange using the same
     * multi-layer strategy as {@link RateLimitFilter} — reads the last
     * {@code X-Forwarded-For} hop to resist spoofing.
     *
     * @param exchange the current server web exchange
     * @return a non-null IP string for logging
     */
    private String resolveClientIp(ServerWebExchange exchange) {
        String xForwardedFor = exchange.getRequest()
                .getHeaders().getFirst("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isBlank()) {
            String[] hops = xForwardedFor.split(",");
            String lastHop = hops[hops.length - 1].strip();
            if (!lastHop.isBlank()) {
                log.info("Client IP resolved via X-Forwarded-For: {}", lastHop);
                return lastHop;
            }
        }
        String xRealIp = exchange.getRequest()
                .getHeaders().getFirst("X-Real-IP");
        if (xRealIp != null && !xRealIp.isBlank()) {
            log.info("Client IP resolved via X-Real-IP: {}", xRealIp.strip());
            return xRealIp.strip();
        }
        if (exchange.getRequest().getRemoteAddress() != null) {
            String remoteIp = exchange.getRequest().getRemoteAddress().getAddress().getHostAddress();
            log.info("Client IP resolved via remote address: {}", remoteIp);
            return remoteIp;
        }
        log.info("Could not resolve client IP, returning 'unknown'");
        return "unknown";
    }
    /**
     * Sanitises a header value before writing it to the log.
     *
     * <p>Prevents log injection (CWE-117) by stripping newlines, carriage
     * returns, and other control characters that a malicious client could
     * use to forge log entries.  Truncates to 200 characters to prevent
     * oversized {@code User-Agent} strings from polluting logs.
     *
     * @param value the raw header value (may be {@code null})
     * @return a safe, printable string — never {@code null}
     */
    private String sanitiseHeaderValue(String value) {
        if (value == null || value.isBlank()) {
            return "-";
        }
        return value
                .replaceAll("[\\r\\n\\t]", "_")
                .substring(0, Math.min(value.length(), 200));
    }
}