package ru.zeker.apigateway.component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import ru.zeker.common.component.HmacUtil;
import ru.zeker.common.config.JwtProperties;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

@Slf4j
@RequiredArgsConstructor
@Component
@EnableConfigurationProperties(JwtProperties.class)
public class JwtValidationFilter implements GlobalFilter, Ordered {
    public static final String BEARER_PREFIX = "Bearer ";

    private final JwtProperties jwtProperties;

    private Key signingKey;

    @PostConstruct
    void init() {
        this.signingKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtProperties.getSecret()));
    }


    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        final String path = exchange.getRequest().getPath().toString();
        final String method = exchange.getRequest().getMethod().name();

        final String header = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (StringUtils.isBlank(header) || !header.startsWith(BEARER_PREFIX)) {
            log.debug("Пропускаем Authorization header для {} {}", method, path);
            return chain.filter(exchange);
        }

        final String jwt = header.substring(BEARER_PREFIX.length());
        log.debug("JWT валидация для {} {}", method, path);

        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(signingKey)
                    .build()
                    .parseClaimsJws(jwt)
                    .getBody();

            if (claims.getSubject() == null || claims.get("role") == null || claims.get("enabled") == null) {
                log.error("Некорректные JWT claims для {} {}. Subject: {}, Role: {}",
                        method, path, claims.getSubject(), claims.get("role"));
                return unauthorized(exchange, "Некорректные claims");
            }

            if (!Boolean.parseBoolean(claims.get("enabled").toString())) {
                log.warn("Неактивный аккаунт для {} {}: {}", method, path, claims.getSubject());
                return unauthorized(exchange, "Аккаунт неактивен");
            }

            log.info("Успешная аутентификация пользователя '{}' (role: {}) для {} {}",
                    claims.getSubject(), claims.get("role"), method, path);

            String username = claims.getSubject();
            String role = claims.get("role", String.class);
            exchange = exchange.mutate()
                    .request(request -> {
                                try {
                                    request
                                            .header("X-User-Name", username)
                                            .header("X-User-Role", role)
                                            .header("X-User-Signature",
                                                    HmacUtil.sign(username + "|" + role, jwtProperties.getSecretHeader(),"HmacSHA256" ));
                                } catch (NoSuchAlgorithmException | InvalidKeyException e) {
                                    log.error("Не удалось подписать JWT", e);
                                    throw new RuntimeException(e);
                                }
                            }
                    )
                    .build();

            return chain.filter(exchange);
        } catch (ExpiredJwtException ex) {
            log.warn("Истек JWT токен для {} {}: {}", method, path, ex.getMessage());
            return unauthorized(exchange, "Токен истек");
        } catch (JwtException | IllegalArgumentException ex) {
            log.error("JWT валидация ошибка для {} {}: {}", method, path, ex.getMessage());
            return unauthorized(exchange, "Токен истек");
        }
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange, String error) {
        log.debug("Возвращаем UNAUTHORIZED (401) for {} {}: {}",
                exchange.getRequest().getMethod(),
                exchange.getRequest().getPath(),
                error);

        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        exchange.getResponse().getHeaders().add("X-Error", error);
        return exchange.getResponse().setComplete();
    }

    @Override
    public int getOrder() {
        return -100; // Высокий приоритет
    }
}
