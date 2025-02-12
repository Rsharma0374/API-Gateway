package in.guardianservices.api_gateway.client;


import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@FeignClient(name = "AUTH-SERVICE")
public interface AuthService {

    @GetMapping("/auth/validate-token/{token}/{username}")
    ResponseEntity<Boolean> validateToken(@PathVariable("token") String token,
                                                 @PathVariable("username") String username);
}
