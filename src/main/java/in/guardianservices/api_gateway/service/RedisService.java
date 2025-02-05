package in.guardianservices.api_gateway.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
public class RedisService {


    @Autowired
    private RedisTemplate<String, Object> redisTemplate;

    /**
     * Store a value in Redis with an expiration time
     * @param key
     * @param value
     * @param expirationTime
     * @param timeUnit
     */
    public void setValueInRedisWithExpiration(String key, Object value, long expirationTime, TimeUnit timeUnit) {
        ValueOperations<String, Object> valueOperations = redisTemplate.opsForValue();
        valueOperations.set(key, value, expirationTime, timeUnit);
    }

    /**
     * Get a value from Redis
     * @param key
     * @return
     */
    public Object getValueFromRedis(String key) {
        ValueOperations<String, Object> valueOperations = redisTemplate.opsForValue();
        return valueOperations.get(key);
    }

    /**
     * Clear a key from Redis
     * @param key
     */
    public void clearKeyFromRedis(String key) {
        redisTemplate.delete(key);
    }
}
