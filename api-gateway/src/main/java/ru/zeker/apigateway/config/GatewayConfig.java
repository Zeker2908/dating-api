package ru.zeker.apigateway.config;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.codec.json.Jackson2JsonEncoder;
import ru.zeker.common.config.JwtProperties;
import ru.zeker.common.util.JwtUtils;

import java.util.concurrent.TimeUnit;

@Configuration
@RequiredArgsConstructor
@Slf4j
public class GatewayConfig {

    @Bean
    public JwtProperties jwtProperties() {
        return new JwtProperties();
    }

    @Bean
    public Cache<String, Claims> claimsCache(JwtProperties jwtProperties) {
        long cacheTtlMs = Math.max(0, jwtProperties.getAccess().getExpiration() - TimeUnit.MINUTES.toMillis(1));
        return CacheBuilder.newBuilder()
                .maximumSize(100_000)
                .expireAfterWrite(cacheTtlMs, TimeUnit.MILLISECONDS)
                .concurrencyLevel(Runtime.getRuntime().availableProcessors() * 2)
                .recordStats()
                .removalListener(notification ->
                        log.debug("Токен выселен: {}, причина: {}",
                                notification.getKey(),
                                notification.getCause()))
                .build();
    }

    @Bean
    public JwtUtils jwtUtils(JwtProperties jwtProperties, Cache<String,Claims> claimsCache) {
        return new JwtUtils(jwtProperties, claimsCache);
    }

    @Bean
    public Jackson2JsonEncoder jsonEncoder() {
        return new Jackson2JsonEncoder();
    }

}
