package in.guardianservices.api_gateway.security;

import com.github.benmanes.caffeine.cache.AsyncLoadingCache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
/**
 * Thread-safe, async JWKS (JSON Web Key Set) cache backed by Caffeine's
 * {@link AsyncLoadingCache}.
 *
 * <h3>Why AsyncLoadingCache?</h3>
 * A plain {@code Cache.getIfPresent()} + conditional fetch pattern suffers from a
 * <em>cache stampede</em>: when the cached entry expires, every concurrent request
 * triggers an independent HTTP call to the JWKS endpoint simultaneously.
 * {@link AsyncLoadingCache} serialises that into a single in-flight
 * {@link CompletableFuture} per key — all waiting threads share the same result.
 *
 * <h3>Circuit Breaker</h3>
 * The JWKS fetch is wrapped in a Resilience4j circuit breaker.  If the remote
 * JWKS endpoint becomes unavailable the circuit opens after a configurable
 * failure threshold, allowing the gateway to fail fast instead of accumulating
 * threads blocked on a hung HTTP connection.
 *
 * <h3>Cache Sizing</h3>
 * JWKS URLs are few (typically one per identity provider), so a maximum of
 * 50 entries is more than sufficient.  1 000 (the original value) was wasteful
 * and could mask an unintended URL-per-request anti-pattern.
 */
@Component
public class JwksCache {

    private static final Logger log = LoggerFactory.getLogger(JwksCache.class);

    /** Circuit-breaker name registered in Resilience4j. */
    private static final String CB_NAME = "jwksFetch";

    /** How long a successfully loaded JWKS is considered fresh. */
    private static final long EXPIRE_AFTER_WRITE_MINUTES = 5;

    /** Maximum number of distinct JWKS URLs to cache (one per identity provider). */
    private static final long MAX_CACHE_SIZE = 50;

    /** HTTP read timeout for a single JWKS fetch attempt. */
    private static final Duration FETCH_TIMEOUT = Duration.ofSeconds(5);

    private final AsyncLoadingCache<String, String> cache;
    private final CircuitBreaker circuitBreaker;
    /**
     * @param webClient shared {@link WebClient} bean — injected by Spring.
     * @param cbRegistry Resilience4j registry — auto-configured by
     *                   {@code resilience4j-spring-boot3} starter.
     */
    public JwksCache(WebClient webClient, CircuitBreakerRegistry cbRegistry) {
        log.info("Initializing JwksCache");
        this.circuitBreaker = buildCircuitBreaker(cbRegistry);
        this.cache = buildCache(webClient);
    }
    // ─────────────────────────────────────────────────────────────────────────
    // Public API
    // ─────────────────────────────────────────────────────────────────────────
    /**
     * Returns the JWKS JSON string for the given URL.
     *
     * <p>On the first call (or after expiry) this triggers a remote HTTP fetch.
     * Concurrent calls for the same URL share a single in-flight request — no
     * stampede.
     *
     * @param jwksUrl the JWKS endpoint URL (e.g. {@code https://idp/.well-known/jwks.json})
     * @return a {@link Mono} that emits the raw JWKS JSON string
     */
    public Mono<String> getJwks(String jwksUrl) {
        if (jwksUrl == null || jwksUrl.isBlank()) {
            log.info("Attempted to fetch JWKS with null or blank URL");
            return Mono.error(new IllegalArgumentException("JWKS URL must not be null or blank"));
        }
        log.info("Requesting JWKS for url={}", jwksUrl);
        return Mono.fromCompletionStage(cache.get(jwksUrl))
                .doOnSubscribe(s -> log.debug("JWKS cache lookup for url={}", jwksUrl))
                .doOnNext(jwks -> log.debug("JWKS cache hit or load complete for url={}", jwksUrl))
                .doOnError(ex -> log.error("JWKS cache load failed for url={}: {}", jwksUrl, ex.getMessage()));
    }
    /**
     * Forcibly evicts the cached JWKS for the given URL so the next request
     * triggers a fresh fetch.  Useful when a key rotation is detected (e.g. a
     * JWT signed by an unknown {@code kid}).
     *
     * @param jwksUrl the JWKS endpoint URL to invalidate
     */
    public void invalidate(String jwksUrl) {
        log.info("Invalidating JWKS cache entry for url={}", jwksUrl);
        cache.synchronous().invalidate(jwksUrl);
    }
    // ─────────────────────────────────────────────────────────────────────────
    // Internal builders
    // ─────────────────────────────────────────────────────────────────────────
    /**
     * Builds the {@link AsyncLoadingCache} with an async loader that calls
     * the JWKS endpoint via {@link WebClient} and wraps the call in the
     * circuit breaker.
     */
    private AsyncLoadingCache<String, String> buildCache(WebClient webClient) {
        log.info("Building AsyncLoadingCache for JWKS");
        return Caffeine.newBuilder()
                .expireAfterWrite(EXPIRE_AFTER_WRITE_MINUTES, TimeUnit.MINUTES)
                .maximumSize(MAX_CACHE_SIZE)
                // refreshAfterWrite keeps the value in cache and proactively
                // refreshes it in the background before it expires, so reads
                // never block on a stale entry.
                .refreshAfterWrite(EXPIRE_AFTER_WRITE_MINUTES - 1, TimeUnit.MINUTES)
                .recordStats() // exposed via Micrometer / Actuator
                .buildAsync((url, executor) ->
                        fetchJwksWithCircuitBreaker(webClient, url).toFuture());
    }
    /**
     * Wraps the actual HTTP fetch in the Resilience4j circuit breaker so the
     * gateway fails fast when the identity provider is unavailable.
     */
    private Mono<String> fetchJwksWithCircuitBreaker(WebClient webClient, String url) {
        log.info("Executing fetchJwksWithCircuitBreaker for url={}", url);
        return Mono.fromCallable(() ->
                        circuitBreaker.executeSupplier(() ->
                                fetchJwksFromUrl(webClient, url).block()))
                .flatMap(result -> result != null
                        ? Mono.just(result)
                        : Mono.error(new JwksFetchException("Empty JWKS response from url=" + url)));
    }
    /**
     * Performs the raw HTTP GET to retrieve the JWKS JSON.
     *
     * <p>Error handling:
     * <ul>
     *   <li>4xx — propagated as {@link JwksFetchException} (bad config, not transient)</li>
     *   <li>5xx — propagated as {@link JwksFetchException} (identity provider error)</li>
     *   <li>Timeout — wrapped as {@link JwksFetchException}</li>
     * </ul>
     */
    private Mono<String> fetchJwksFromUrl(WebClient webClient, String url) {
        log.info("Fetching JWKS from remote url={}", url);
        return webClient.get()
                .uri(url)
                .retrieve()
                .onStatus(
                        status -> status.is4xxClientError(),
                        response -> Mono.error(new JwksFetchException(
                                "Client error fetching JWKS from url=" + url
                                        + " status=" + response.statusCode()))
                )
                .onStatus(
                        status -> status.is5xxServerError(),
                        response -> Mono.error(new JwksFetchException(
                                "Server error fetching JWKS from url=" + url
                                        + " status=" + response.statusCode()))
                )
                .bodyToMono(String.class)
                .timeout(FETCH_TIMEOUT)
                .doOnNext(body -> log.info("Successfully fetched JWKS from url={}", url))
                .doOnNext(body -> log.debug("Successfully fetched JWKS from url={}", url))
                .onErrorMap(
                        ex -> !(ex instanceof JwksFetchException),
                        ex -> new JwksFetchException("Unexpected error fetching JWKS from url=" + url, ex)
                );
    }
    /**
     * Builds and registers a Resilience4j {@link CircuitBreaker} for JWKS fetches.
     *
     * <p>Configuration:
     * <ul>
     *   <li>Opens after 5 failures in a 10-call sliding window.</li>
     *   <li>Stays open for 30 seconds before entering HALF_OPEN.</li>
     *   <li>Allows 3 test calls in HALF_OPEN before deciding to close or re-open.</li>
     *   <li>Counts both exceptions and slow calls (> 3 s) as failures.</li>
     * </ul>
     */
    private CircuitBreaker buildCircuitBreaker(CircuitBreakerRegistry registry) {
        log.info("Building circuit breaker for JWKS fetch");
        CircuitBreakerConfig config = CircuitBreakerConfig.custom()
                .slidingWindowType(CircuitBreakerConfig.SlidingWindowType.COUNT_BASED)
                .slidingWindowSize(10)
                .failureRateThreshold(50.0f)          // 50 % of calls must fail to open
                .slowCallRateThreshold(50.0f)
                .slowCallDurationThreshold(Duration.ofSeconds(3))
                .waitDurationInOpenState(Duration.ofSeconds(30))
                .permittedNumberOfCallsInHalfOpenState(3)
                .recordExceptions(JwksFetchException.class, WebClientResponseException.class)
                .build();
        return registry.circuitBreaker(CB_NAME, config);
    }
    // ─────────────────────────────────────────────────────────────────────────
    // Domain exception
    // ─────────────────────────────────────────────────────────────────────────
    /**
     * Thrown when the JWKS endpoint cannot be reached or returns an error.
     * Treated as a transient infrastructure failure — never exposed to clients.
     */
    public static final class JwksFetchException extends RuntimeException {
        public JwksFetchException(String message) {
            super(message);
        }
        public JwksFetchException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}