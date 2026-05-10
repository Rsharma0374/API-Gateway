package in.guardianservices.api_gateway.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RateLimitConfig {
    private static final Logger log = LoggerFactory.getLogger(RateLimitConfig.class);

    public RateLimitConfig() {
        log.info("Initializing RateLimitConfig");
    }
}