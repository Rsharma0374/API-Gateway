package in.guardianservices.api_gateway.exception;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JwtVerificationException extends RuntimeException {
    private static final Logger log = LoggerFactory.getLogger(JwtVerificationException.class);

    public JwtVerificationException(String message) {
        super(message);
        log.info("JwtVerificationException created with message: {}", message);
    }
    public JwtVerificationException(String message, Throwable cause) {
        super(message, cause);
        log.info("JwtVerificationException created with message: {} and cause: {}", message, cause.getMessage());
    }
}