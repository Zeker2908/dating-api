package ru.zeker.api_gateway.component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.PathMatcher;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.security.Key;
import java.util.List;

@Component
public class JwtValidationFilter implements GlobalFilter, Ordered {
    public static final String BEARER_PREFIX = "Bearer ";

    private static final Logger log = LoggerFactory.getLogger(JwtValidationFilter.class);

    //TODO: Придумать как перенести это в конифиги
    private static final List<String> EXCLUDED_PATHS = List.of(
            "/api/v1/auth/**"
    );

    //TODO: Переделать с HMAC на RS256
    @Value("${jwt.secret}")
    private String jwtSigningKey;

    private Key signingKey;
    private final PathMatcher pathMatcher = new AntPathMatcher();

    @PostConstruct
    void init() {
        this.signingKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSigningKey));
    }


    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        final String path = exchange.getRequest().getPath().toString();
        final String method = exchange.getRequest().getMethod().name();

        if (EXCLUDED_PATHS.stream().anyMatch(pattern -> pathMatcher.match(pattern, path))) {
            log.debug("Skipping JWT validation for {} {}", method, path);
            return chain.filter(exchange);
        }

        final String header = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (StringUtils.isBlank(header)) {
            log.warn("Missing Authorization header for {} {}", method, path);
            return unauthorized(exchange, "Missing token");
        }

        if (!header.startsWith(BEARER_PREFIX)) {
            log.warn("Invalid Authorization header format for {} {}", method, path);
            return unauthorized(exchange, "Invalid token format");
        }

        final String jwt = header.substring(BEARER_PREFIX.length());
        log.debug("JWT validation started for {} {}", method, path);

        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(signingKey)
                    .build()
                    .parseClaimsJws(jwt)
                    .getBody();

            if (claims.getSubject() == null || claims.get("role") == null) {
                log.error("Invalid JWT claims for {} {}. Subject: {}, Role: {}",
                        method, path, claims.getSubject(), claims.get("role"));
                return unauthorized(exchange, "Invalid claims");
            }

            log.info("Successful authentication for user '{}' (role: {}) via {} {}",
                    claims.getSubject(), claims.get("role"), method, path);

            exchange = exchange.mutate()
                    .request(request -> request
                            .header("X-User-Name", claims.getSubject())
                            .header("X-User-Role", claims.get("role", String.class))
                    )
                    .build();

            return chain.filter(exchange);
        } catch (ExpiredJwtException ex) {
            log.warn("Expired JWT for {} {}: {}", method, path, ex.getMessage());
            return unauthorized(exchange, "Token expired");
        } catch (JwtException | IllegalArgumentException ex) {
            log.error("JWT validation failed for {} {}: {}", method, path, ex.getMessage());
            return unauthorized(exchange, "Invalid token");
        }
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange, String error) {
        log.debug("Returning UNAUTHORIZED (401) for {} {}: {}",
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
