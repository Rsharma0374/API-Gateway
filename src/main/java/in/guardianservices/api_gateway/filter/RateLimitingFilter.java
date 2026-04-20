package in.guardianservices.api_gateway.filter;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class RateLimitingFilter implements GlobalFilter, Ordered {

    // Store a TokenBucket for each IP address + API path combination
    private final Map<String, TokenBucket> clientBuckets = new ConcurrentHashMap<>();

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String clientIp = getClientIp(exchange);
        String apiPath = exchange.getRequest().getPath().toString();
        
        // Create a unique key combining the client's IP and the API they are accessing
        String rateLimitKey = clientIp + ":" + apiPath;

        // Configuration: Allow max 5 requests burst, and refill tokens every 30 seconds per API endpoint
        TokenBucket bucket = clientBuckets.computeIfAbsent(rateLimitKey, k -> new TokenBucket(5, 30));

        if (bucket.tryConsume()) {
            // Token available, continue with the request
            return chain.filter(exchange);
        } else {
            // No tokens available, reject the request with 429 Too Many Requests and custom JSON body
            return handleRateLimitExceeded(exchange.getResponse(), bucket.getSecondsUntilRefill());
        }
    }

    private Mono<Void> handleRateLimitExceeded(ServerHttpResponse response, long secondsUntilRefill) {
        response.setStatusCode(HttpStatus.TOO_MANY_REQUESTS);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        
        String jsonResponse = String.format("""
            {
              "error": "Too many requests",
              "message": "You have exceeded the rate limit. Please try again later.",
              "retry_after": %d
            }""", secondsUntilRefill);

        DataBuffer buffer = response.bufferFactory().wrap(jsonResponse.getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Mono.just(buffer));
    }

    private String getClientIp(ServerWebExchange exchange) {
        // First check X-Forwarded-For header in case the gateway is behind a load balancer/proxy
        String ip = exchange.getRequest().getHeaders().getFirst("X-Forwarded-For");
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            if (exchange.getRequest().getRemoteAddress() != null) {
                ip = exchange.getRequest().getRemoteAddress().getAddress().getHostAddress();
            }
        } else {
            // X-Forwarded-For can be a comma-separated list of IPs. The first one is the original client.
            ip = ip.split(",")[0].trim();
        }
        return ip != null ? ip : "unknown";
    }

    @Override
    public int getOrder() {
        return -100; // Execute early in the gateway filter chain
    }

    /**
     * Basic Token Bucket Algorithm Implementation
     */
    private static class TokenBucket {
        private final long capacity;
        private final long refillIntervalSeconds;
        private double tokens;
        private long lastRefillTimestamp;

        public TokenBucket(long capacity, long refillIntervalSeconds) {
            this.capacity = capacity;
            this.refillIntervalSeconds = refillIntervalSeconds;
            this.tokens = capacity;
            this.lastRefillTimestamp = System.currentTimeMillis();
        }

        public synchronized boolean tryConsume() {
            refill();
            if (tokens >= 1) {
                tokens -= 1;
                return true;
            }
            return false;
        }

        public synchronized long getSecondsUntilRefill() {
            long now = System.currentTimeMillis();
            long elapsedMillis = now - lastRefillTimestamp;
            long refillIntervalMillis = refillIntervalSeconds * 1000;
            
            if (elapsedMillis >= refillIntervalMillis) {
                return 0; // Ready to refill right now
            }
            
            // Calculate remaining seconds, rounded up
            return (refillIntervalMillis - elapsedMillis + 999) / 1000;
        }

        private void refill() {
            long now = System.currentTimeMillis();
            long elapsedMillis = now - lastRefillTimestamp;
            long refillIntervalMillis = refillIntervalSeconds * 1000;
            
            if (elapsedMillis >= refillIntervalMillis) {
                // If interval has passed, fully refill the bucket
                tokens = capacity;
                lastRefillTimestamp = now;
            }
        }
    }
}
