package in.guardianservices.api_gateway.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

public class ResponseUtility {

    private static final Logger logger = LoggerFactory.getLogger(ResponseUtility.class);


    public static Properties fetchProperties(String userAuthPropertiesPath) {
        Properties properties = new Properties();
        try {
            properties.load(new FileInputStream(userAuthPropertiesPath));
            return properties;
        } catch (IOException e) {
            logger.error("Exception occurred while getting user auth config with probable cause - ", e);
            return null;
        }
    }

    public static Mono<Void> handleError(ServerWebExchange exchange, String message) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        // Construct JSON response using HashMap
        Map<String, Object> jsonResponse = new HashMap<>();
        Map<String, Object> status = new HashMap<>();
        status.put("iStatus", 401);
        status.put("sStatus", "UNAUTHORIZED");
        jsonResponse.put("oStatus", status);

        Map<String, Object> errorDetails = new HashMap<>();
        errorDetails.put("sId", null);
        errorDetails.put("sFieldName", null);
        errorDetails.put("sErrorType", "SYSTEM");
        errorDetails.put("sErrorCode", "401");
        errorDetails.put("sMessage", "Access Denied !! " + message);
        errorDetails.put("sLevel", null);
        errorDetails.put("oUser", null);
        errorDetails.put("dFieldValue", 0.0);
        errorDetails.put("aWhatsNew", null);

        jsonResponse.put("aError", List.of(errorDetails));

        byte[] bytes = new byte[0];
        try {
            bytes = new ObjectMapper().writeValueAsBytes(jsonResponse);
        } catch (JsonProcessingException e) {
            logger.error("Exception occurred while writing json response", e);
        }

        DataBuffer buffer = response.bufferFactory().wrap(bytes);
        return response.writeWith(Mono.just(buffer));
    }
}
