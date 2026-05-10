package in.guardianservices.api_gateway.filter;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Counter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.TimeUnit;
/**
 * Third filter in the gateway chain ({@code @Order(3)}).
 *
 * <p>Enforces per-client IP rate limiting using the token-bucket algorithm
 * (Bucket4j v8) to protect downstream services from traffic spikes, brute-force
 * attempts, and denial-of-service attacks.
 *
 * <h3>Problems fixed from original implementation</h3>
 * <ul>
 *   <li><strong>Unbounded map:</strong> The original used a raw
 *       {@link java.util.concurrent.ConcurrentHashMap} that grew forever.
 *       Millions of unique or spoofed IPs would exhaust heap memory.
 *       This implementation uses a <strong>Caffeine cache</strong> with a
 *       bounded size and TTL-based eviction.</li>
 *
 *   <li><strong>Deprecated Bucket4j API:</strong> The original used
 *       {@code Bucket4j.builder()} and {@code Bandwidth.classic()} which
 *       were removed in Bucket4j v5+.  This implementation uses the current
 *       {@code Bucket.builder()} and {@code Bandwidth.builder()} API.</li>
 *
 *   <li><strong>Missing {@code Refill} import:</strong> The original referenced
 *       {@code Refill.intervally()} without importing it, causing a compile
 *       error.  The new API does not require a separate {@code Refill} class.</li>
 *
 *   <li><strong>Field injection of {@code @Value} after construction:</strong>
 *       The original used field-level {@code @Value} injection, meaning
 *       {@code newBucket()} could observe default primitive values (0) if
 *       called during construction.  This implementation uses
 *       <strong>constructor injection</strong> so all values are guaranteed
 *       to be set before any method executes.</li>
 *
 *   <li><strong>NullPointerException on {@code getRemoteAddress()}:</strong>
 *       The original called {@code getRemoteAddress().getAddress().getHostAddress()}
 *       without a null check.  This is null when running behind a proxy or in
 *       test environments.  This implementation resolves the client IP safely
 *       with a multi-layer fallback strategy.</li>
 *
 *   <li><strong>X-Forwarded-For spoofing:</strong> Accepting the first value
 *       of {@code X-Forwarded-For} blindly allows a malicious client to spoof
 *       any IP and bypass rate limiting entirely.  This implementation reads
 *       the <em>last</em> value in the {@code X-Forwarded-For} chain — the one
 *       appended by the trusted edge proxy — which cannot be spoofed by the
 *       client.</li>
 * </ul>
 *
 * <h3>Token bucket algorithm</h3>
 * Each unique client IP gets its own {@link Bucket}.  A bucket starts with
 * {@code capacity} tokens and is refilled by {@code refillTokens} every
 * {@code refillPeriodMs} milliseconds.  Each request consumes one token.
 * When the bucket is empty the request is rejected with {@code 429}.
 *
 * <h3>Configuration ({@code application.yml})</h3>
 * <pre>{@code
 * ratelimit:
 *   capacity:        100     # max burst — tokens at full bucket
 *   refill-tokens:   10      # tokens added per refill period
 *   refill-period-ms: 60000  # refill interval in milliseconds (1 minute)
 *   cache-max-size:  100000  # max unique IPs tracked simultaneously
 *   cache-ttl-hours: 1       # evict idle IPs after this many hours
 * }</pre>
 *
 * <h3>Observability</h3>
 * Two Micrometer counters are published:
 * <ul>
 *   <li>{@code gateway.ratelimit.allowed} — requests that consumed a token.</li>
 *   <li>{@code gateway.ratelimit.rejected} — requests rejected with {@code 429}.</li>
 * </ul>
 * These appear at {@code /actuator/metrics} and are scraped by Prometheus.
 */
@Component
@Order(3)
public class RateLimitFilter implements WebFilter {

    private static final Logger log = LoggerFactory.getLogger(RateLimitFilter.class);

    /** Response header telling the client when the rate-limit window resets. */
    private static final String HEADER_RETRY_AFTER = "Retry-After";

    /** Response header exposing remaining tokens (informational). */
    private static final String HEADER_RATE_LIMIT_REMAINING = "X-RateLimit-Remaining";

    /** Response header exposing the bucket capacity (informational). */
    private static final String HEADER_RATE_LIMIT_LIMIT = "X-RateLimit-Limit";

    // ── Rate-limit configuration (constructor-injected) ──────────────────────
    private final long capacity;
    private final long refillTokens;
    private final Duration refillPeriod;

    // ── Caffeine-backed, bounded bucket map ──────────────────────────────────
    private final Cache<String, Bucket> buckets;

    // ── Micrometer metrics ───────────────────────────────────────────────────
    private final Counter allowedCounter;
    private final Counter rejectedCounter;
    /**
     * All configuration values are injected through the constructor so that
     * field values are guaranteed to be present before {@link #newBucket(String)}
     * is ever called — eliminating the "zero-capacity bucket" race condition
     * present in the original field-injected implementation.
     *
     * @param capacity        maximum token capacity (burst size)
     * @param refillTokens    tokens added per refill period
     * @param refillPeriodMs  refill period in milliseconds
     * @param cacheMaxSize    maximum number of unique IPs to track
     * @param cacheTtlHours   idle-eviction TTL in hours
     * @param meterRegistry   Micrometer registry for publishing metrics
     */
    public RateLimitFilter(
            @Value("${ratelimit.capacity}") long capacity,
            @Value("${ratelimit.refill-tokens}") long refillTokens,
            @Value("${ratelimit.refill-period-ms}") long refillPeriodMs,
            @Value("${ratelimit.cache-max-size:100000}") long cacheMaxSize,
            @Value("${ratelimit.cache-ttl-hours:1}") long cacheTtlHours,
            MeterRegistry meterRegistry) {
        this.capacity = capacity;
        this.refillTokens = refillTokens;
        this.refillPeriod = Duration.ofMillis(refillPeriodMs);
        this.buckets = Caffeine.newBuilder()
                .maximumSize(cacheMaxSize)
                // Evict idle entries — prevents memory exhaustion from unique/spoofed IPs.
                // expireAfterAccess: entry is evicted if not accessed for cacheTtlHours.
                .expireAfterAccess(cacheTtlHours, TimeUnit.HOURS)
                .recordStats()
                .build();
        // Register Micrometer counters — visible at /actuator/metrics
        this.allowedCounter = Counter.builder("gateway.ratelimit.allowed")
                .description("Number of requests allowed through the rate limiter")
                .register(meterRegistry);
        this.rejectedCounter = Counter.builder("gateway.ratelimit.rejected")
                .description("Number of requests rejected by the rate limiter (HTTP 429)")
                .register(meterRegistry);
        log.info("RateLimitFilter initialised — capacity={}, refillTokens={}, "
                        + "refillPeriod={}, cacheMaxSize={}, cacheTtlHours={}",
                capacity, refillTokens, refillPeriod, cacheMaxSize, cacheTtlHours);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // WebFilter
    // ─────────────────────────────────────────────────────────────────────────
    /**
     * Attempts to consume one token from the bucket assigned to the client IP.
     *
     * <ul>
     *   <li>Token available → allows the request, sets informational headers.</li>
     *   <li>No token available → returns {@code 429 Too Many Requests} with a
     *       {@code Retry-After} header and an RFC 7807 Problem+JSON body.</li>
     * </ul>
     */
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        log.info("Evaluating rate limit for request to {}", exchange.getRequest().getURI().getPath());
        String clientIp = resolveClientIp(exchange);
        Bucket bucket = buckets.get(clientIp, this::newBucket);
        // tryConsumeAndReturnRemaining() is non-blocking and thread-safe.
        var probe = bucket.tryConsumeAndReturnRemaining(1);
        if (probe.isConsumed()) {
            allowedCounter.increment();
            log.info("Rate limit token consumed. Remaining tokens: {} for IP: {}", probe.getRemainingTokens(), clientIp);
            log.trace("Rate limit OK — clientIp={} remainingTokens={}",
                    clientIp, probe.getRemainingTokens());
            // Expose rate-limit state to the client (informational).
            exchange.getResponse().getHeaders()
                    .set(HEADER_RATE_LIMIT_LIMIT, String.valueOf(capacity));
            exchange.getResponse().getHeaders()
                    .set(HEADER_RATE_LIMIT_REMAINING, String.valueOf(probe.getRemainingTokens()));
            return chain.filter(exchange);
        }
        // Token exhausted — compute wait time and reject.
        long retryAfterSeconds = Math.ceilDiv(
                probe.getNanosToWaitForRefill(), 1_000_000_000L);
        rejectedCounter.increment();
        log.info("Rate limit exceeded for IP: {}. Rejecting request.", clientIp);
        log.warn("Rate limit exceeded — clientIp={} retryAfterSeconds={}",
                clientIp, retryAfterSeconds);
        return tooManyRequests(exchange, clientIp, retryAfterSeconds);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Client IP resolution
    // ─────────────────────────────────────────────────────────────────────────
    /**
     * Resolves the true client IP address using a multi-layer strategy designed
     * to work correctly behind reverse proxies while resisting IP spoofing.
     *
     * <h3>Resolution order</h3>
     * <ol>
     *   <li><strong>{@code X-Forwarded-For} — last value:</strong>
     *       When a request passes through a chain of proxies, each proxy appends
     *       its own IP.  The <em>last</em> value is appended by the trusted edge
     *       proxy and cannot be forged by the client.  Reading the <em>first</em>
     *       value (as the original code did) allows any client to claim any IP.</li>
     *   <li><strong>{@code X-Real-IP}:</strong> Set by Nginx when configured with
     *       {@code proxy_set_header X-Real-IP $remote_addr}.  Trusted only when
     *       your edge proxy is Nginx and it is configured correctly.</li>
     *   <li><strong>{@code getRemoteAddress()}:</strong>  The TCP-level peer address.
     *       Reliable when there is no proxy, but always the proxy IP when proxied.</li>
     *   <li><strong>Fallback {@code "unknown"}:</strong>  Used only in environments
     *       where no address is available (e.g. some unit-test contexts).  Requests
     *       from "unknown" share a single bucket — intentionally conservative.</li>
     * </ol>
     *
     * <p><strong>Production recommendation:</strong> Configure your edge proxy
     * (AWS ALB, Nginx, Envoy) to set {@code X-Forwarded-For} reliably and strip
     * any client-supplied values of the same header before they reach the gateway.
     *
     * @param exchange the current server web exchange
     * @return a non-null, non-blank IP string to use as the bucket key
     */
    private String resolveClientIp(ServerWebExchange exchange) {
        // ── Strategy 1: X-Forwarded-For (last hop = trusted edge proxy) ──────
        String xForwardedFor = exchange.getRequest()
                .getHeaders().getFirst("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isBlank()) {
            String[] hops = xForwardedFor.split(",");
            String lastHop = hops[hops.length - 1].strip();
            if (!lastHop.isBlank()) {
                log.info("Resolved client IP from X-Forwarded-For (last hop): {}", lastHop);
                log.trace("Client IP resolved from X-Forwarded-For (last hop): {}", lastHop);
                return lastHop;
            }
        }
        // ── Strategy 2: X-Real-IP (Nginx) ────────────────────────────────────
        String xRealIp = exchange.getRequest()
                .getHeaders().getFirst("X-Real-IP");
        if (xRealIp != null && !xRealIp.isBlank()) {
            log.info("Resolved client IP from X-Real-IP: {}", xRealIp);
            log.trace("Client IP resolved from X-Real-IP: {}", xRealIp);
            return xRealIp.strip();
        }
        // ── Strategy 3: TCP remote address ───────────────────────────────────
        if (exchange.getRequest().getRemoteAddress() != null) {
            String remoteIp = exchange.getRequest()
                    .getRemoteAddress().getAddress().getHostAddress();
            log.info("Resolved client IP from RemoteAddress: {}", remoteIp);
            log.trace("Client IP resolved from RemoteAddress: {}", remoteIp);
            return remoteIp;
        }
        // ── Strategy 4: Fallback ──────────────────────────────────────────────
        log.info("Falling back client IP to 'unknown'");
        log.warn("Could not resolve client IP — falling back to 'unknown' bucket");
        return "unknown";
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Bucket factory
    // ─────────────────────────────────────────────────────────────────────────
    /**
     * Creates a new token-bucket for the given client key using the Bucket4j v8
     * {@code Bandwidth.builder()} API.
     *
     * <p>The bucket is configured with:
     * <ul>
     *   <li><strong>capacity</strong> — maximum burst size.</li>
     *   <li><strong>refillIntervally</strong> — adds {@code refillTokens} every
     *       {@code refillPeriod} as a single batch (not greedy/gradual).  This
     *       creates a clean "N requests per minute" semantic.</li>
     *   <li><strong>initialTokens(capacity)</strong> — starts full so the first
     *       request is never rejected.</li>
     * </ul>
     *
     * @param clientKey the client IP address (used only for logging)
     * @return a new, fully configured {@link Bucket}
     */
    private Bucket newBucket(String clientKey) {
        log.info("Creating new rate limit bucket for client IP: {}", clientKey);
        Bandwidth limit = Bandwidth.builder()
                .capacity(capacity)
                .refillIntervally(refillTokens, refillPeriod)
                .initialTokens(capacity)
                .build();
        log.debug("Created new rate-limit bucket — clientKey={} capacity={} "
                        + "refillTokens={} refillPeriod={}",
                clientKey, capacity, refillTokens, refillPeriod);
        return Bucket.builder()
                .addLimit(limit)
                .build();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Error response
    // ─────────────────────────────────────────────────────────────────────────
    /**
     * Writes a {@code 429 Too Many Requests} response with:
     * <ul>
     *   <li>{@code Retry-After} header — seconds until the bucket refills.</li>
     *   <li>{@code X-RateLimit-Limit} header — total bucket capacity.</li>
     *   <li>RFC 7807 {@code application/problem+json} body.</li>
     * </ul>
     *
     * <p>The client IP is <strong>never</strong> included in the response body —
     * only in internal log statements.
     */
    private Mono<Void> tooManyRequests(
            ServerWebExchange exchange,
            String clientIp,
            long retryAfterSeconds) {
        log.info("Generating 429 Too Many Requests response for IP: {}", clientIp);
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.TOO_MANY_REQUESTS);
        response.getHeaders().setContentType(MediaType.APPLICATION_PROBLEM_JSON);
        response.getHeaders().set(HEADER_RETRY_AFTER, String.valueOf(retryAfterSeconds));
        response.getHeaders().set(HEADER_RATE_LIMIT_LIMIT, String.valueOf(capacity));
        return Mono.deferContextual(ctx -> {
            String requestId = ctx.getOrDefault(
                    RequestIdFilter.REQUEST_ID_CONTEXT_KEY, "none");
            String body = String.format(
                    """
                    {
                      "type":        "https://httpstatuses.com/429",
                      "title":       "Too Many Requests",
                      "status":      429,
                      "detail":      "Rate limit exceeded. Please retry after %d second(s).",
                      "retryAfter":  %d,
                      "requestId":   "%s"
                    }
                    """,
                    retryAfterSeconds, retryAfterSeconds, requestId);
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            DataBuffer buffer = response.bufferFactory().wrap(bytes);
            return response.writeWith(Mono.just(buffer));
        });
    }
}