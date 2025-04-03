package ru.zeker.api_gateway.component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.apache.commons.lang.StringUtils;
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

    //TODO: Переделать с HMAC на RS256
    @Value("${jwt.secret}")
    private String jwtSigningKey;

    //TODO: Придумать как перенести это в конифиги
    private static final List<String> EXCLUDED_PATHS = List.of(
            "/api/v1/auth/**"
    );

    private Key signingKey;
    private final PathMatcher pathMatcher = new AntPathMatcher();

    @PostConstruct
    void init() {
        this.signingKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSigningKey));
    }


    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        final String path = exchange.getRequest().getPath().toString();

        if (EXCLUDED_PATHS.stream().anyMatch(pattern -> pathMatcher.match(pattern, path))) {
            return chain.filter(exchange);
        }

        final String header = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (StringUtils.isBlank(header) || !header.startsWith(BEARER_PREFIX)) {
            return unauthorized(exchange, "Missing token");
        }

        final String jwt = header.substring(BEARER_PREFIX.length());

        if (StringUtils.isNotEmpty(jwt)){
            try{
               Claims claims = Jwts.parserBuilder()
                        .setSigningKey(signingKey)
                        .build()
                        .parseClaimsJws(jwt)
                        .getBody();

                if (claims.getSubject() == null || claims.get("role") == null) {
                    return unauthorized(exchange, "Invalid claims");
                }

                exchange = exchange.mutate()
                        .request(request -> request
                                .header("X-User-Name", claims.getSubject())
                                .header("X-User-Role", claims.get("role", String.class))
                        )
                        .build();

               return chain.filter(exchange);
            } catch (ExpiredJwtException ex) {
                return unauthorized(exchange, "Token expired");
            } catch (JwtException | IllegalArgumentException ex) {
                return unauthorized(exchange, "Invalid token");
            }

        }
        return exchange.getResponse().setComplete();
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange, String error) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        exchange.getResponse().getHeaders().add("X-Error", error);
        return exchange.getResponse().setComplete();
    }

    @Override
    public int getOrder() {
        return -100; // Высокий приоритет
    }
}
