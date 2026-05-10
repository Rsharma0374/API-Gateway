package in.guardianservices.api_gateway.security;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
/**
 * Single source of truth for all publicly accessible paths in the gateway —
 * i.e., paths that bypass JWT authentication.
 *
 * <h3>Why this class exists</h3>
 * The original codebase duplicated the public-path list in two places:
 * <ul>
 *   <li>{@code JwtVerificationFilter} — hardcoded {@code List.of("/health", "/public")}</li>
 *   <li>{@code PublicPathRegistry} — hardcoded {@code Set.of("/health", "/public", "/fallback")}</li>
 * </ul>
 * The two lists had already diverged ({@code /fallback} was missing from the filter),
 * creating a silent security inconsistency.  This class eliminates that duplication:
 * every component that needs to know whether a path is public must inject and query
 * this registry — never maintain its own list.
 *
 * <h3>Configuration-driven</h3>
 * Paths are externalised to {@code application.yml} under the
 * {@code gateway.public-paths} key and are loaded at startup via
 * {@link ConfigurationProperties}.  Adding or removing a public path requires
 * only a config change — no code change, no redeployment of logic.
 *
 * <h3>Ant-style pattern matching</h3>
 * Paths support Ant-style wildcards via Spring's {@link AntPathMatcher}:
 * <ul>
 *   <li>{@code /public/**} — matches {@code /public/anything/nested}</li>
 *   <li>{@code /fallback/*}  — matches {@code /fallback/service} but not {@code /fallback/a/b}</li>
 *   <li>{@code /health}      — exact match</li>
 * </ul>
 *
 * <h3>Validation at startup</h3>
 * {@link #validatePaths()} runs on {@link PostConstruct} and fails fast if:
 * <ul>
 *   <li>The path list is empty (every route would require auth, which may
 *       break liveness probes).</li>
 *   <li>Any path entry is blank or does not start with {@code /}.</li>
 * </ul>
 *
 * <h3>Thread safety</h3>
 * After the {@link PostConstruct} phase the internal list is replaced with an
 * unmodifiable copy.  All subsequent reads are safe for concurrent use without
 * synchronisation.
 *
 * <h3>Example {@code application.yml}</h3>
 * <pre>{@code
 * gateway:
 *   public-paths:
 *     - /health
 *     - /actuator/health/**
 *     - /public/**
 *     - /fallback/**
 * }</pre>
 */
@Component
@ConfigurationProperties(prefix = "gateway")
public class PublicPathRegistry {

    private static final Logger log = LoggerFactory.getLogger(PublicPathRegistry.class);

    /**
     * Ant path matcher — thread-safe, stateless after construction.
     * Handles wildcard patterns like {@code /public/**} and {@code /fallback/*}.
     */
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    /**
     * Mutable during Spring binding; replaced with an unmodifiable list in
     * {@link #validatePaths()}.  Populated by Spring Boot's
     * {@link ConfigurationProperties} binding from {@code gateway.public-paths}.
     */
    private List<String> publicPaths = new ArrayList<>();

    // ─────────────────────────────────────────────────────────────────────────
    // ConfigurationProperties setter — required for Spring binding
    // ─────────────────────────────────────────────────────────────────────────
    /**
     * Called by Spring Boot's {@link ConfigurationProperties} binder to inject
     * the {@code gateway.public-paths} list from {@code application.yml}.
     *
     * <p><strong>Do not call this method directly.</strong>
     *
     * @param publicPaths list of Ant-style path patterns that bypass authentication
     */
    public void setPublicPaths(List<String> publicPaths) {
        log.info("Setting public paths: {}", publicPaths);
        this.publicPaths = publicPaths != null ? new ArrayList<>(publicPaths) : new ArrayList<>();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Lifecycle
    // ─────────────────────────────────────────────────────────────────────────
    /**
     * Validates the injected path list and seals it as unmodifiable.
     * Runs after all Spring properties have been bound.
     *
     * @throws IllegalStateException if the list is empty or any entry is invalid
     */
    @PostConstruct
    public void validatePaths() {
        log.info("Validating public paths");
        if (publicPaths.isEmpty()) {
            log.info("Validation failed: gateway.public-paths is empty");
            throw new IllegalStateException(
                    "gateway.public-paths must not be empty. "
                            + "At minimum, '/actuator/health/**' should be public "
                            + "so Kubernetes liveness/readiness probes can reach it.");
        }
        List<String> invalid = publicPaths.stream()
                .filter(p -> p == null || p.isBlank() || !p.startsWith("/"))
                .toList();
        if (!invalid.isEmpty()) {
            log.info("Validation failed: invalid path entries found: {}", invalid);
            throw new IllegalStateException(
                    "gateway.public-paths contains invalid entries (must start with '/'): "
                            + invalid);
        }
        // Seal — all subsequent reads are from an unmodifiable list.
        this.publicPaths = Collections.unmodifiableList(publicPaths);
        log.info("PublicPathRegistry initialised with {} public path pattern(s): {}",
                publicPaths.size(), publicPaths);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Public API
    // ─────────────────────────────────────────────────────────────────────────
    /**
     * Returns {@code true} if the given request path matches any registered
     * public-path pattern, meaning the request may proceed without a valid JWT.
     *
     * <p>Matching uses Ant-style pattern semantics:
     * <ul>
     *   <li>{@code ?} — matches exactly one character</li>
     *   <li>{@code *} — matches zero or more characters within a single segment</li>
     *   <li>{@code **} — matches zero or more path segments</li>
     * </ul>
     *
     * @param requestPath the URI path of the incoming HTTP request
     *                    (e.g. {@code /actuator/health/liveness})
     * @return {@code true} if authentication should be skipped for this path
     */
    public boolean isPublicPath(String requestPath) {
        log.info("Checking if path '{}' is public", requestPath);
        if (requestPath == null || requestPath.isBlank()) {
            log.info("Path is null or blank, treating as protected");
            log.warn("isPublicPath() called with a null or blank path — treating as protected");
            return false;
        }
        boolean isPublic = publicPaths.stream()
                .anyMatch(pattern -> pathMatcher.match(pattern, requestPath));
        if (isPublic) {
            log.info("Path '{}' matches a public pattern", requestPath);
            log.trace("Path '{}' matched a public pattern — skipping authentication", requestPath);
        } else {
            log.info("Path '{}' is not public", requestPath);
        }
        return isPublic;
    }
    /**
     * Returns an unmodifiable view of all registered public-path patterns.
     * Intended for diagnostic endpoints and test assertions — not for matching.
     *
     * @return immutable list of Ant-style path patterns
     */
    public List<String> getPublicPaths() {
        return publicPaths; // already unmodifiable after @PostConstruct
    }
}