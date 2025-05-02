package ru.zeker.apigateway.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.codec.json.Jackson2JsonEncoder;
import ru.zeker.common.util.JwtUtils;
import ru.zeker.common.config.JwtProperties;

@Configuration
@RequiredArgsConstructor
public class GatewayConfig {

    @Bean
    public JwtProperties jwtProperties() {
        return new JwtProperties();
    }

    @Bean
    public JwtUtils jwtUtils(JwtProperties jwtProperties) {
        return new JwtUtils(jwtProperties);
    }

    @Bean
    public Jackson2JsonEncoder jsonEncoder() {
        return new Jackson2JsonEncoder();
    }

}
