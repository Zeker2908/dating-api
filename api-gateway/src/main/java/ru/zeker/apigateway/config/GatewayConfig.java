package ru.zeker.apigateway.config;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.codec.json.Jackson2JsonEncoder;
import ru.zeker.common.util.JwtUtils;
import ru.zeker.common.config.JwtProperties;

import java.util.concurrent.TimeUnit;

@Configuration
@RequiredArgsConstructor
public class GatewayConfig {

    @Bean
    public JwtProperties jwtProperties() {
        return new JwtProperties();
    }

    @Bean
    public Cache<String, Claims> claimsCache(JwtProperties jwtProperties) {
        return CacheBuilder.newBuilder()
                .maximumSize(5000)
                .expireAfterWrite(jwtProperties.getAccess().getExpiration()-1, TimeUnit.MINUTES)
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
