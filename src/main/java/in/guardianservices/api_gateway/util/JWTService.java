package in.guardianservices.api_gateway.util;

import in.guardianservices.api_gateway.service.RedisService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

@Service
public class JWTService {

    @Autowired
    private RedisService redisService;

    private static String secretKey = "";
    public static final String SECRET_KEY = "SECRET_KEY";
    private static final String USER_AUTH_PROPERTIES_PATH = "/opt/configs/userAuth.properties";

    static {
        Properties properties = ResponseUtility.fetchProperties(USER_AUTH_PROPERTIES_PATH);
        if (null != properties) {
            secretKey = properties.getProperty(SECRET_KEY);
        }
    }


    private SecretKey getKey() {
        byte[] keyByte = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyByte);
    }

    public String extractUserName(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public boolean validateToken(String token, String requestUsername) {
        final String username = extractUserName(token);
        return (username.equals(requestUsername) && !isTokenExpired(token));
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }
}
