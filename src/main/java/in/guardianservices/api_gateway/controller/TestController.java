package in.guardianservices.api_gateway.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/internal-test")
public class TestController {

    @GetMapping("/rate-limit")
    public Mono<String> testRateLimit() {
        return Mono.just("Success! Request passed through the Rate Limiting Filter.");
    }

    @GetMapping("/rate-limit2")
    public Mono<String> testRateLimit2() {
        return Mono.just("Success! Request passed through the Rate Limiting Filter2.");
    }
}
