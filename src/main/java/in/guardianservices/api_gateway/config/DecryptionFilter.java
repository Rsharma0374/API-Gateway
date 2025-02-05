package in.guardianservices.api_gateway.config;

import in.guardianservices.api_gateway.security.AESUtil;
import in.guardianservices.api_gateway.service.RedisService;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.factory.rewrite.ModifyRequestBodyGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Map;

@Component
public class DecryptionFilter implements GlobalFilter {
    private static final Logger log = LoggerFactory.getLogger(DecryptionFilter.class);

    private final ModifyRequestBodyGatewayFilterFactory modifyRequestBodyGatewayFilterFactory;

    public DecryptionFilter(ModifyRequestBodyGatewayFilterFactory modifyRequestBodyGatewayFilterFactory) {
        this.modifyRequestBodyGatewayFilterFactory = modifyRequestBodyGatewayFilterFactory;
    }

    @Autowired
    private RedisService redisService;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        String id = exchange.getRequest().getHeaders().getFirst("sKeyId");
        String key = StringUtils.isBlank(id) ? null
                : (String) redisService.getValueFromRedis(id);

        ServerHttpRequest request = exchange.getRequest();

        if ("GET".equalsIgnoreCase(request.getMethod().name())) {
            return chain.filter(exchange);
        } else {
            return handlePostRequest(exchange, chain, key);
        }
    }


    private Mono<Void> handlePostRequest(ServerWebExchange exchange, GatewayFilterChain chain, String key) {
        return exchange.getRequest().getBody()
                .next()
                .flatMap(dataBuffer -> {
                    byte[] bytes = new byte[dataBuffer.readableByteCount()];
                    dataBuffer.read(bytes);
                    String encryptedBody = new String(bytes, StandardCharsets.UTF_8);
                    String decryptedBody = decryptRequestBody(encryptedBody, key);

                    return modifyRequestBodyGatewayFilterFactory.apply(
                            new ModifyRequestBodyGatewayFilterFactory.Config()
                                    .setRewriteFunction(String.class, String.class, (exchange1, originalBody) -> Mono.just(decryptedBody))
                    ).filter(exchange, chain);
                });
    }

    private String decryptRequestBody(String jsonString, String key) {
        try {
            int startIndex = jsonString.indexOf(":") + 2;
            int endIndex = jsonString.lastIndexOf("\"");
            String encryptedText = jsonString.substring(startIndex, endIndex);
            return AESUtil.decrypt(encryptedText, key);
        } catch (Exception e) {
            log.error("Decryption failed", e);
            return jsonString; // Fallback to original if decryption fails
        }
    }


}
