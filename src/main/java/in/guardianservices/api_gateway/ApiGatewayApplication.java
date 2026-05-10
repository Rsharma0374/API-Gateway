package in.guardianservices.api_gateway;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.Clock;

@SpringBootApplication
public class ApiGatewayApplication {
	private static final Logger log = LoggerFactory.getLogger(ApiGatewayApplication.class);

	public static void main(String[] args) {
		log.info("Starting ApiGatewayApplication...");
		SpringApplication.run(ApiGatewayApplication.class, args);
		log.info("ApiGatewayApplication started successfully");
	}

	/**
	 * Shared WebClient bean used across the application (e.g., JWKS fetching).
	 * Configured with sensible defaults:
	 *   - JSON Accept header so JWKS endpoints respond correctly.
	 *   - Codecs limited to 1 MB to prevent memory exhaustion on large responses.
	 */
	@Bean
	public WebClient webClient() {
		log.info("Initializing WebClient bean");
		return WebClient.builder()
				.defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
				.codecs(configurer ->
						configurer.defaultCodecs().maxInMemorySize(1024 * 1024)) // 1 MB
				.build();
	}

	/**
	 * System UTC clock bean injected into {@link in.guardianservices.api_gateway.security.JwtVerifier}
	 * for {@code exp} and {@code nbf} claim validation.
	 *
	 * <p>Defining it as a bean (rather than hardcoding {@code Clock.systemUTC()} inside
	 * JwtVerifier) makes the verifier fully testable — unit tests can inject a
	 * {@link Clock#fixed(java.time.Instant, java.time.ZoneId)} instance to simulate
	 * expired or future-dated tokens without sleeping or manipulating system time.
	 *
	 * <pre>{@code
	 * // In a unit test:
	 * Clock frozenClock = Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC);
	 * JwtVerifier verifier = new JwtVerifier(jwksCache, issuer, audience, frozenClock);
	 * }</pre>
	 */
	@Bean
	public Clock clock() {
		log.info("Initializing System UTC Clock bean");
		return Clock.systemUTC();
	}

}