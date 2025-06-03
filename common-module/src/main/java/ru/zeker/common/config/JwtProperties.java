package ru.zeker.common.config;

import lombok.Data;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;


@Data
@Configuration
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {
    private Resource privateKeyPath;
    private Resource publicKeyPath;
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