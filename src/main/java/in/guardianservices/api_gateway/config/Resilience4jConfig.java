package in.guardianservices.api_gateway.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Resilience4jConfig {
    private static final Logger log = LoggerFactory.getLogger(Resilience4jConfig.class);

    public Resilience4jConfig() {
        log.info("Initializing Resilience4jConfig");
    }
}