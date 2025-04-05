package ru.zeker.common.config;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.List;


@Data
@Configuration
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {
    private List<String> excludedPaths;
    private String secret;
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