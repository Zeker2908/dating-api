package ru.zeker.api_gateway.component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
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

import java.util.Arrays;
import java.util.List;

@Component
public class JwtValidationFilter implements GlobalFilter, Ordered {
    public static final String BEARER_PREFIX = "Bearer ";

    @Value("${jwt.secret}")
    private String jwtSigningKey;

    private static final List<String> EXCLUDED_PATHS = Arrays.asList(
            "/api/v1/auth/login",
            "/api/v1/auth/register"
    );

    private final PathMatcher pathMatcher = new AntPathMatcher();


    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getPath().toString();

        if (EXCLUDED_PATHS.stream().anyMatch(pattern -> pathMatcher.match(pattern, path))) {
            return chain.filter(exchange);
        }

        final String header = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        final String jwt;

        if (StringUtils.isEmpty(header) || !StringUtils.startsWith(header, BEARER_PREFIX)){
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        jwt = header.substring(BEARER_PREFIX.length());

        if (StringUtils.isNotEmpty(jwt)){
            try{
               Claims claims = Jwts.parserBuilder()
                        .setSigningKey(Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSigningKey)))
                        .build()
                        .parseClaimsJws(jwt)
                        .getBody();

                if (!claims.containsKey("sub") || !claims.containsKey("role")) {
                    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                    return exchange.getResponse().setComplete();
                }

                exchange = exchange.mutate()
                        .request(request -> request
                                .header("X-User-Name", claims.getSubject())
                                .header("X-User-Role", claims.get("role", String.class))
                        )
                        .build();

               return chain.filter(exchange);
            } catch (ExpiredJwtException expiredJwtException){
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                exchange.getResponse().getHeaders().add("X-Error", "Token expired");
            }  catch (JwtException | IllegalArgumentException ex) {
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                exchange.getResponse().getHeaders().add("X-Error", "Invalid token");
            }

        }
        return exchange.getResponse().setComplete();
    }

    @Override
    public int getOrder() {
        return -100; // Высокий приоритет
    }
}
