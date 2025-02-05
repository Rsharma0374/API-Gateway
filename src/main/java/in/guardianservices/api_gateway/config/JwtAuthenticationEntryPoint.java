package in.guardianservices.api_gateway.config;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Component
public class JwtAuthenticationEntryPoint implements ServerAuthenticationEntryPoint {
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public Mono<Void> commence(ServerWebExchange exchange, org.springframework.security.core.AuthenticationException ex) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);

        // Construct JSON response using HashMap
        Map<String, Object> jsonResponse = new HashMap<>();
        Map<String, Object> status = new HashMap<>();
        status.put("iStatus", 401);
        status.put("sStatus", "UNAUTHORIZED");
        jsonResponse.put("oStatus", status);

        Map<String, Object> errorDetails = new HashMap<>();
        errorDetails.put("sErrorType", "SYSTEM");
        errorDetails.put("sErrorCode", "401");
        errorDetails.put("sMessage", "Access Denied !! " + ex.getMessage());

        jsonResponse.put("aError", List.of(errorDetails));

        byte[] bytes = null;
        try {
            bytes = objectMapper.writeValueAsBytes(jsonResponse);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }

        DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bytes);

        return exchange.getResponse().writeWith(Mono.just(buffer));
    }
}
