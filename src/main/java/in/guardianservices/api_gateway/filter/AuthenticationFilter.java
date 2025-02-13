package in.guardianservices.api_gateway.filter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import in.guardianservices.api_gateway.constants.PublicEndpoint;
import in.guardianservices.api_gateway.security.AESUtil;
import in.guardianservices.api_gateway.service.RedisService;
import in.guardianservices.api_gateway.util.JWTService;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.bouncycastle.util.Strings;
import org.reactivestreams.Publisher;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.OrderedGatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.cloud.gateway.filter.factory.rewrite.CachedBodyOutputMessage;
import org.springframework.cloud.gateway.filter.factory.rewrite.MessageBodyDecoder;
import org.springframework.cloud.gateway.filter.factory.rewrite.MessageBodyEncoder;
import org.springframework.cloud.gateway.support.BodyInserterContext;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.core.io.buffer.DefaultDataBufferFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ReactiveHttpOutputMessage;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.BodyInserter;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.server.HandlerStrategies;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import static java.util.function.Function.identity;

@Component
@Slf4j
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {


    @Autowired
    private RedisService redisService;

    @Autowired
    private JWTService jwtService;

    public AuthenticationFilter(Set<MessageBodyDecoder> messageBodyDecoders,
                                Set<MessageBodyEncoder> messageBodyEncoders){
        super(Config.class);
        this.messageBodyDecoders = messageBodyDecoders.stream()
                .collect(Collectors.toMap(MessageBodyDecoder::encodingType, identity()));
        this.messageBodyEncoders = messageBodyEncoders.stream()
                .collect(Collectors.toMap(MessageBodyEncoder::encodingType, identity()));
    }


    public static class Config {

    }


    private final Map<String, MessageBodyDecoder> messageBodyDecoders;

    private final Map<String, MessageBodyEncoder> messageBodyEncoders;


    @Override
    public GatewayFilter apply(Config config) {
        return new OrderedGatewayFilter((exchange, chain) -> {
            try {
                ServerHttpRequest request = exchange.getRequest();
                String url = request.getURI().getPath();

                boolean isPublicEndPoint = PublicEndpoint.isPublicEndpoint(url);
                boolean isDecryptionRequired = PublicEndpoint.requiresDecryption(url);
                boolean isTokenRequired = PublicEndpoint.tokenRequired(url);

                if (isPublicEndPoint && !isDecryptionRequired) {
                    return chain.filter(exchange);
                }

                if (isTokenRequired) {
                    String token = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
                    String username = request.getHeaders().getFirst("userName");
                    if (token == null || !token.startsWith("Bearer ")) {
                        return handleError(exchange, "Authorization header is not valid");
                    }
                    token = token.substring(7);
                    try {
                        String jwtToken = (String) redisService.getValueFromRedis(token);
                        jwtService.validateToken(jwtToken, username);
                    } catch (RuntimeException e) {
                        return handleError(exchange, "Authorization header not present");
                    }
                }

                log.info("Applying encrypt-decrypt filter");

                return DataBufferUtils.join(exchange.getRequest().getBody())
                        .flatMap(dataBuffer -> {
                            try {
                                ServerHttpRequest mutatedHttpRequest = getServerHttpRequest(exchange, dataBuffer);
                                ServerHttpResponse mutatedHttpResponse = getServerHttpResponse(exchange);
                                return chain.filter(exchange.mutate()
                                        .request(mutatedHttpRequest)
                                        .response(mutatedHttpResponse)
                                        .build());
                            } catch (Exception e) {
                                log.error("Error processing request", e);
                                return handleError(exchange, e.getMessage());
                            }
                        })
                        .onErrorResume(e -> {
                            log.error("Error in filter chain", e);
                            return handleError(exchange, e.getMessage());
                        });

            } catch (Exception e) {
                log.error("Error in authentication filter", e);
                return handleError(exchange, e.getMessage());
            }
        }, -2);
    }

    private ServerHttpRequest getServerHttpRequest(ServerWebExchange exchange, DataBuffer dataBuffer) throws Exception {

        String id = exchange.getRequest().getHeaders().getFirst("sKeyId");
            String key = StringUtils.isBlank(id) ? null
                    : (String) redisService.getValueFromRedis(id);

        // Retain the data buffer to prevent memory leaks
        DataBufferUtils.retain(dataBuffer);
        Flux<DataBuffer> cachedFlux = Flux.defer(() -> Flux.just(dataBuffer.slice(0, dataBuffer.readableByteCount())));

        // Convert request body to raw string
        String rawBody = toRaw(cachedFlux);
        log.info("🔹 Raw Request Body: " + rawBody);

        // Extract the "encryptedPayload" field if JSON
        String encryptedPayload;
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            JsonNode jsonNode = objectMapper.readTree(rawBody);
            encryptedPayload = jsonNode.get("encryptedPayload").asText();
            log.info("🔹 Extracted Encrypted Payload: " + encryptedPayload);
        } catch (Exception e) {
            throw new RuntimeException("Invalid JSON format! Expected {\"encryptedPayload\": \"...\"}", e);
        }

        // Decrypt the extracted payload
        String decryptedBody = AESUtil.decrypt(encryptedPayload, key);
        log.info("🔐 Decrypted Request Body: " + decryptedBody);
        byte[] decryptedBodyBytes = decryptedBody.getBytes(StandardCharsets.UTF_8);

        return new ServerHttpRequestDecorator(exchange.getRequest()) {

            @Override
            public HttpHeaders getHeaders(){
                HttpHeaders httpHeaders = new HttpHeaders();
                httpHeaders.putAll(exchange.getRequest().getHeaders());
                if (decryptedBodyBytes.length > 0) {
                    httpHeaders.setContentLength(decryptedBodyBytes.length);
                }
                httpHeaders.set(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON.toString());
                return httpHeaders;
            }


            @Override
            public Flux<DataBuffer> getBody() {
                return Flux.just(new DefaultDataBufferFactory().wrap(decryptedBodyBytes));
            }

        };


    }

    private ServerHttpResponse getServerHttpResponse(ServerWebExchange exchange) {
        ServerHttpResponse originalResponse = exchange.getResponse();

        String id = exchange.getRequest().getHeaders().getFirst("sKeyId");
        String key = StringUtils.isBlank(id) ? null
                : (String) redisService.getValueFromRedis(id);
        if (exchange.getRequest().getURI().getPath().equalsIgnoreCase(PublicEndpoint.AUTH_LOGOUT.getPath())) {
            redisService.clearKeyFromRedis(id);
        }
        return new ServerHttpResponseDecorator(originalResponse) {

            @Override
            public Mono<Void> writeWith(Publisher<? extends DataBuffer> body) {

                HttpHeaders httpHeaders = new HttpHeaders();
                httpHeaders.set(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON.toString());
                httpHeaders.set(HttpHeaders.CONTENT_ENCODING, "application/octet-stream");

                ClientResponse clientResponse = prepareClientResponse(body, httpHeaders);

                Mono<String> modifiedBody = extractBody(exchange, clientResponse)
                        .flatMap( originalBody -> {
                            try {

                                String encryptedResponse = AESUtil.encrypt(originalBody, key);
                                return Mono.just("{\"sResponse\": \"" + encryptedResponse + "\"}"); // ✅ Wrap in JSON
                            } catch (Exception e) {
                                throw new RuntimeException(e);
                            }
                        })
                        .switchIfEmpty(Mono.empty());

                BodyInserter<Mono<String>, ReactiveHttpOutputMessage> bodyInserter = BodyInserters.fromPublisher(modifiedBody, String.class);

                CachedBodyOutputMessage outputMessage = new CachedBodyOutputMessage(exchange,
                        exchange.getResponse().getHeaders());

                return bodyInserter.insert(outputMessage, new BodyInserterContext())
                        .then(Mono.defer(() -> {
                            Mono<DataBuffer> messageBody = updateBody(getDelegate(), outputMessage);
                            HttpHeaders headers = getDelegate().getHeaders();
                            headers.setContentType(MediaType.TEXT_PLAIN);
                            if (headers.containsKey(HttpHeaders.CONTENT_LENGTH)) {
                                messageBody = messageBody.doOnNext(data -> {
                                    headers.setContentLength(data.readableByteCount());
                                });
                            }

                            return getDelegate().writeWith(messageBody);
                        }));

            }

            private Mono<String> extractBody(ServerWebExchange exchange1, ClientResponse clientResponse) {

                List<String> encodingHeaders = exchange.getResponse().getHeaders()
                        .getOrEmpty(HttpHeaders.CONTENT_ENCODING);
                for (String encoding : encodingHeaders) {
                    MessageBodyDecoder decoder = messageBodyDecoders.get(encoding);
                    if (decoder != null) {
                        return clientResponse.bodyToMono(byte[].class)
                                .publishOn(Schedulers.parallel()).map(decoder::decode)
                                .map(bytes -> exchange.getResponse().bufferFactory()
                                        .wrap(bytes))
                                .map(buffer -> prepareClientResponse(Mono.just(buffer),
                                        exchange.getResponse().getHeaders()))
                                .flatMap(response -> response.bodyToMono(String.class));
                    }
                }


                return clientResponse.bodyToMono(String.class);

            }

            private Mono<DataBuffer> updateBody(ServerHttpResponse httpResponse,
                                                CachedBodyOutputMessage message) {

                Mono<DataBuffer> response = DataBufferUtils.join(message.getBody());

                List<String> encodingHeaders = httpResponse.getHeaders()
                        .getOrEmpty(HttpHeaders.CONTENT_ENCODING);
                for (String encoding : encodingHeaders) {
                    MessageBodyEncoder encoder = messageBodyEncoders.get(encoding);
                    if (encoder != null) {
                        DataBufferFactory dataBufferFactory = httpResponse.bufferFactory();
                        response = response.publishOn(Schedulers.parallel())
                                .map(encoder::encode).map(dataBufferFactory::wrap);
                        break;
                    }
                }

                return response;

            }



            private ClientResponse prepareClientResponse(Publisher<? extends DataBuffer> body, HttpHeaders httpHeaders) {
                ClientResponse.Builder builder = ClientResponse.create(exchange.getResponse().getStatusCode(), HandlerStrategies.withDefaults().messageReaders());
                return builder.headers(headers -> headers.putAll(httpHeaders)).body(Flux.from(body)).build();
            }

        };
    }


    private static String toRaw(Flux<DataBuffer> body) {
        AtomicReference<String> rawRef = new AtomicReference<>();
        body.subscribe(buffer -> {
            byte[] bytes = new byte[buffer.readableByteCount()];
            buffer.read(bytes);
            DataBufferUtils.release(buffer);
            rawRef.set(Strings.fromUTF8ByteArray(bytes));
        });
        return rawRef.get();
    }

    private Mono<Void> handleError(ServerWebExchange exchange, String message) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        Map<String, Object> jsonResponse = new HashMap<>();
        Map<String, Object> status = new HashMap<>();
        status.put("iStatus", 401);
        status.put("sStatus", "UNAUTHORIZED");
        jsonResponse.put("oStatus", status);

        Map<String, Object> errorDetails = new HashMap<>();
        errorDetails.put("sErrorType", "SYSTEM");
        errorDetails.put("sErrorCode", "401");
        errorDetails.put("sMessage", "Access Denied !! " + message);
        errorDetails.put("dFieldValue", 0.0);

        jsonResponse.put("aError", List.of(errorDetails));

        byte[] bytes = new byte[0];
        try {
            bytes = new ObjectMapper().writeValueAsBytes(jsonResponse);
        } catch (JsonProcessingException e) {
            log.error("Error while converting json to bytes", e);
        }

        DataBuffer buffer = response.bufferFactory().wrap(bytes);
        return response.writeWith(Mono.just(buffer));
    }


}
