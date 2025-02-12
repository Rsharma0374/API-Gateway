package in.guardianservices.api_gateway.filter;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.function.Predicate;

@Component
public class RouteValidator {

    public static final List<String> OPEN_API_PATHS = List.of(
            "/user/hello",
            "auth/user-login",
            "/auth/validate-token",
            "/communications/validate-otp-reset-password",
            "/communications/validate-email-otp",
            "/auth/create-user",
            "/eureka");

    public Predicate<ServerHttpRequest> isSecured =
            req -> OPEN_API_PATHS
                    .stream()
                    .noneMatch(uri -> req.getURI().getPath().contains(uri));
}
