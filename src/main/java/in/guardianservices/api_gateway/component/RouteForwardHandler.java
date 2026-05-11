package in.guardianservices.api_gateway.component;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.client.ServiceInstance;
import org.springframework.cloud.client.loadbalancer.LoadBalancerClient;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.server.ServerRequest;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Component
public class RouteForwardHandler {

    @Autowired
    private LoadBalancerClient loadBalancerClient;

    @Autowired
    private WebClient.Builder webClientBuilder;

    public Mono<ResponseEntity<byte[]>> forwardToService(String serviceName, String path, ServerRequest request) {
        // Resolve service from Consul
        ServiceInstance instance = loadBalancerClient.choose(serviceName);
        if (instance == null) {
            return Mono.error(new RuntimeException("No available instance for service: " + serviceName));
        }

        String baseUrl = instance.getUri().toString();

        // Build the full path with query parameters
        String fullPath = path;
        String query = request.uri().getRawQuery();
        if (query != null && !query.isEmpty()) {
            fullPath = path + "?" + query;
        }

        // Get the request body as DataBuffer flux
        Flux<DataBuffer> bodyFlux = request.bodyToFlux(DataBuffer.class);

        return webClientBuilder
                .baseUrl(baseUrl)
                .build()
                .method(request.method())
                .uri(fullPath)
                .headers(headers -> headers.addAll(request.headers().asHttpHeaders()))
                .body(BodyInserters.fromDataBuffers(bodyFlux))
                .exchangeToMono(response ->
                        response.bodyToMono(byte[].class)
                                .map(body -> ResponseEntity
                                        .status(response.statusCode())
                                        .headers(headers -> headers.addAll(response.headers().asHttpHeaders()))
                                        .body(body)
                                )
                );
    }
}