package ru.zeker.common.config;

import lombok.Data;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;


@Data
@Configuration
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {
    private String privateKey;
    private String publicKey;
    private Access access;
    private Refresh refresh;

    @Data
    public static class Access {
        private long expiration;
    }

    @Data
    public static class Refresh {
        private long expiration;
    }
}