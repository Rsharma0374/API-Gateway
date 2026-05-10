package in.guardianservices.api_gateway.web;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class FallbackController {
    private static final Logger log = LoggerFactory.getLogger(FallbackController.class);

    public FallbackController() {
        log.info("Initializing FallbackController");
    }
}