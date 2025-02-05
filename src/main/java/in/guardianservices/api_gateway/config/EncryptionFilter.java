package in.guardianservices.api_gateway.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import in.guardianservices.api_gateway.security.AESUtil;
import in.guardianservices.api_gateway.service.RedisService;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.factory.rewrite.ModifyResponseBodyGatewayFilterFactory;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

@Component
public class EncryptionFilter implements GlobalFilter, Ordered {
    private static final Logger log = LoggerFactory.getLogger(EncryptionFilter.class);
    private final ModifyResponseBodyGatewayFilterFactory modifyResponseBodyGatewayFilterFactory;

    @Autowired
    private RedisService redisService;

    public EncryptionFilter(ModifyResponseBodyGatewayFilterFactory modifyResponseBodyGatewayFilterFactory) {
        this.modifyResponseBodyGatewayFilterFactory = modifyResponseBodyGatewayFilterFactory;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String id = exchange.getRequest().getHeaders().getFirst("sKeyId");
        log.debug("Received sKeyId: {}", id);

        String key = StringUtils.isBlank(id) ? null : (String) redisService.getValueFromRedis(id);
        log.warn("Retrieved encryption key present: {}", (key != null));

        ModifyResponseBodyGatewayFilterFactory.Config config = new ModifyResponseBodyGatewayFilterFactory.Config();
        config.setRewriteFunction(byte[].class, byte[].class, (exchange1, originalBody) -> {
            if (originalBody == null) {
                log.warn("Received null response body");
                return Mono.just(new byte[0]);
            }

            String bodyStr = new String(originalBody, StandardCharsets.UTF_8);
            log.debug("Original response body: {}", bodyStr);

            return encryptResponseBody(bodyStr, key)
                    .map(encrypted -> encrypted.getBytes(StandardCharsets.UTF_8));
        });

        return modifyResponseBodyGatewayFilterFactory.apply(config)
                .filter(exchange, chain);
    }

    private Mono<String> encryptResponseBody(String responseBody, String key) {
        try {
            log.debug("Starting encryption process");

            if (StringUtils.isBlank(key)) {
                log.warn("Encryption key is blank or null, returning original response");
                return Mono.just(responseBody);
            }

            if (StringUtils.isBlank(responseBody)) {
                log.warn("Response body is blank or null");
                return Mono.just(responseBody);
            }

            log.debug("Attempting to encrypt response body");
            String encryptedText = AESUtil.encrypt(responseBody, key);
            log.debug("Encryption successful: {}", (encryptedText != null));

            String wrappedResponse = "{\"sResponse\":\"" + encryptedText + "\"}";
            log.debug("Final wrapped response created");

            return Mono.just(wrappedResponse);

        } catch (Exception e) {
            log.error("Exception occurred while encrypting response: ", e);
            return Mono.just(responseBody);
        }
    }

    @Override
    public int getOrder() {
        // Set to run after other filters but before response is sent
        return HIGHEST_PRECEDENCE + 2;
    }
}
