package in.guardianservices.api_gateway.controller;

import in.guardianservices.api_gateway.security.AESUtil;
import in.guardianservices.api_gateway.service.RedisService;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@RestController
@RequestMapping("/gateway")
public class HomeController {
    private static Logger logger = LoggerFactory.getLogger(HomeController.class);

    @PostConstruct
    public void init() {
        logger.warn("HomeController initialized");
    }

    @Autowired
    private RedisService redisService;

    @GetMapping("/key")
    public ResponseEntity<Map<String, String>> getEncryptionKey() {
        try {
            logger.warn("Getting encryption key");
            // Generate AES encryption key
            String encodedKey = AESUtil.generateKey();
            logger.warn("Key: {}", encodedKey);

            // Generate unique session ID
            UUID uuid = UUID.randomUUID();
            logger.warn("UUID: {}", uuid);

            // Store the key in Redis with a 1-hour expiration
            redisService.setValueInRedisWithExpiration(uuid.toString(), encodedKey, (60 * 60), TimeUnit.SECONDS);

            logger.warn("Rest in redis: {}", true);
            // Prepare response data
            Map<String, String> response = new HashMap<>();
            response.put("sKey", encodedKey);
            response.put("sId", uuid.toString());

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("Exception occurred while getting encryption key", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Collections.singletonMap("error", "Failed to generate key"));
        }
    }
}
