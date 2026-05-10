package in.guardianservices.api_gateway.web;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class HealthController {
    private static final Logger log = LoggerFactory.getLogger(HealthController.class);

    public HealthController() {
        log.info("Initializing HealthController");
    }
}