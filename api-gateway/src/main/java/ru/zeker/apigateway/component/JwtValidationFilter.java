package ru.zeker.apigateway.component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import ru.zeker.apigateway.exception.AuthException;
import ru.zeker.common.util.JwtUtils;

import java.util.Optional;

import static ru.zeker.common.headers.ApiHeaders.*;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtValidationFilter implements GlobalFilter, Ordered {
    private static final String BEARER_PREFIX = "Bearer ";
    private static final String REQUIRES_AUTH_KEY = "auth-required";
    private static final String REQUIRED_ROLE_KEY = "required-role";

    private final JwtUtils jwtUtils;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return checkIfAuthRequired(exchange)
                .flatMap(authRequired -> {
                    if (!authRequired) {
                        return chain.filter(exchange);
                    }
                    return extractAndValidateToken(exchange)
                            .flatMap(claims -> verifyAuthorization(exchange, claims))
                            .flatMap(claims -> chain.filter(addUserHeaders(exchange, claims)));
                })
                .onErrorResume(AuthException.class, ex -> handleAuthError(exchange, ex));
    }

    private Mono<Boolean> checkIfAuthRequired(ServerWebExchange exchange) {
        return Mono.fromCallable(() -> {
            Route route = exchange.getAttribute(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR);
            return Optional.ofNullable(route)
                    .map(Route::getMetadata)
                    .map(metadata -> Boolean.parseBoolean(metadata.getOrDefault(REQUIRES_AUTH_KEY, "true").toString()))
                    .orElse(true);
        });
    }

    private Mono<Claims> extractAndValidateToken(ServerWebExchange exchange) {
        return Mono.fromCallable(() -> {
            String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

            if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
                throw new AuthException("Нет заголовка " + HttpHeaders.AUTHORIZATION, HttpStatus.UNAUTHORIZED);
            }

            String token = authHeader.substring(BEARER_PREFIX.length());
            try {
                if (jwtUtils.isTokenExpired(token)) {
                    throw new AuthException("Токен истек", HttpStatus.UNAUTHORIZED);
                }
                return jwtUtils.extractAllClaims(token);
            } catch (JwtException e) {
                throw new AuthException(e.getMessage(), HttpStatus.UNAUTHORIZED);
            }
        });
    }

    private Mono<Claims> verifyAuthorization(ServerWebExchange exchange, Claims claims) {
        return Mono.fromCallable(() -> {
            String userRole = claims.get("role", String.class);
            if (userRole == null) {
                throw new AuthException("Роль пользователя не указана в токене", HttpStatus.FORBIDDEN);
            }

            String requiredRole = getRequiredRole(exchange);

            if (requiredRole != null && !requiredRole.equals(userRole)) {
                throw new AuthException("Недостаточно привилегий", HttpStatus.FORBIDDEN);
            }
            return claims;
        });
    }

    private String getRequiredRole(ServerWebExchange exchange) {
        Route route = exchange.getAttribute(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR);
        return Optional.ofNullable(route)
                .map(Route::getMetadata)
                .map(metadata -> metadata.get(REQUIRED_ROLE_KEY))
                .map(Object::toString)
                .orElse(null);
    }

    private ServerWebExchange addUserHeaders(ServerWebExchange exchange, Claims claims) {
        ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                .header(X_USER_ID_KEY, claims.get("id", String.class))
                .header(X_USER_NAME_HEADER, claims.getSubject())
                .header(X_USER_ROLE_HEADER, claims.get("role", String.class))
                .build();

        return exchange.mutate().request(mutatedRequest).build();
    }

    private Mono<Void> handleAuthError(ServerWebExchange exchange, AuthException ex) {
        log.warn("Ошибка авторизации: {}, {}, {}",
                ex.getMessage(),
                exchange.getRequest().getMethod(),
                exchange.getRequest().getPath());

        exchange.getResponse().setStatusCode(ex.getStatus());
        exchange.getResponse().getHeaders().set(X_ERROR_HEADER, ex.getMessage());
        return exchange.getResponse().setComplete();
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }
}
