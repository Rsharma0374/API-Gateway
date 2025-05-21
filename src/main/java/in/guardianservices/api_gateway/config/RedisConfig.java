package in.guardianservices.api_gateway.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.connection.RedisPassword;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.jedis.JedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.util.CollectionUtils;

import java.util.Map;

@Slf4j
@Configuration
@AutoConfigureAfter(RedisAutoConfiguration.class)
@EnableCaching
public class RedisConfig {

    @Bean
    public JedisConnectionFactory jedisConnectionFactory() throws Exception {
        Map config = InfisicalConfig.fetchConfig("RedisSecret");
        RedisStandaloneConfiguration redisConfig = new RedisStandaloneConfiguration();
        redisConfig.setHostName(CollectionUtils.isEmpty(config) ? "localhost" : config.get("host").toString());
        redisConfig.setPort(CollectionUtils.isEmpty(config) ? 6379 : Integer.parseInt((String) config.get("port")));
        redisConfig.setPassword(RedisPassword.of(CollectionUtils.isEmpty(config) ? null : (String) config.get("password")));
        return new JedisConnectionFactory(redisConfig);

    }

    @Bean
    public RedisTemplate<String, Object> redisTemplate() throws Exception {
        RedisTemplate<String, Object> redisTemplate = new RedisTemplate<>();
        redisTemplate.setConnectionFactory(jedisConnectionFactory());
        redisTemplate.setKeySerializer(new StringRedisSerializer());
        redisTemplate.setValueSerializer(new GenericJackson2JsonRedisSerializer());
        return redisTemplate;
    }
}
