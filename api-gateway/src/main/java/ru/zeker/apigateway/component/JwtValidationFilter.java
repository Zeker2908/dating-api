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
import org.springframework.core.ResolvableType;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.codec.json.Jackson2JsonEncoder;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import ru.zeker.apigateway.exception.AuthException;
import ru.zeker.common.util.JwtUtils;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import static ru.zeker.common.headers.ApiHeaders.*;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtValidationFilter implements GlobalFilter, Ordered {
    private static final String BEARER_PREFIX     = "Bearer ";
    private static final String AUTH_REQUIRED_KEY = "auth-required";
    private static final String REQUIRED_ROLE_KEY = "required-role";

    private final JwtUtils jwtUtils;
    private final Jackson2JsonEncoder jsonEncoder;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return isAuthRequired(exchange)
                .flatMap(required -> {
                    if (!required) {
                        return chain.filter(exchange);
                    }
                    return extractClaims(exchange)
                            .flatMap(claims -> verifyRole(exchange, claims))
                            .flatMap(claims -> chain.filter(withUserHeaders(exchange, claims)));
                })
                .onErrorResume(AuthException.class, ex -> writeError(exchange, ex));
    }

    private Mono<Boolean> isAuthRequired(ServerWebExchange exchange) {
        Route route = exchange.getAttribute(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR);
        boolean required = Optional.ofNullable(route)
                .map(Route::getMetadata)
                .map(meta -> Boolean.parseBoolean(meta.getOrDefault(AUTH_REQUIRED_KEY, "true").toString()))
                .orElse(true);
        return Mono.just(required);
    }

    private Mono<Claims> extractClaims(ServerWebExchange exchange) {
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            return Mono.error(new AuthException("Отсутствует заголовок авторизации", HttpStatus.UNAUTHORIZED));
        }

        String token = authHeader.substring(BEARER_PREFIX.length());

        return Mono.fromCallable(() -> {
                    try {
                        if (jwtUtils.isTokenExpired(token)) {
                            throw new AuthException("Срок действия токена истек", HttpStatus.UNAUTHORIZED);
                        }
                        return jwtUtils.extractAllClaims(token);
                    } catch (JwtException e) {
                        log.warn("Недействительный JWT: {}", e.getMessage());
                        throw new AuthException("Недействительный токен", HttpStatus.UNAUTHORIZED);
                    } catch (Exception e) {
                        log.warn("Не удалось проанализировать токен {}", e.getMessage());
                        throw new AuthException("Недействительный токен", HttpStatus.UNAUTHORIZED);
                    }
                })
                .subscribeOn(Schedulers.boundedElastic());
    }

    private Mono<Claims> verifyRole(ServerWebExchange exchange, Claims claims) {
        String userRole = claims.get("role", String.class);
        if (userRole == null) {
            log.warn("Роль пользователя не указана в токене");
            return Mono.error(new AuthException("Роль пользователя не указана в токене", HttpStatus.FORBIDDEN));
        }
        Route route = exchange.getAttribute(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR);
        String requiredRole = Optional.ofNullable(route)
                .map(Route::getMetadata)
                .map(meta -> meta.get(REQUIRED_ROLE_KEY))
                .map(Object::toString)
                .orElse(null);
        if (requiredRole != null && !requiredRole.equals(userRole)) {
            log.warn("Недостаточно привилегий");
            return Mono.error(new AuthException("Недостаточно привилегий", HttpStatus.FORBIDDEN));
        }
        return Mono.just(claims);
    }

    private ServerWebExchange withUserHeaders(ServerWebExchange exchange, Claims claims) {
        ServerHttpRequest mutated = exchange.getRequest().mutate()
                .header(USER_ID, claims.get("id", String.class))
                .header(USER_NAME, claims.getSubject())
                .header(USER_ROLE, claims.get("role", String.class))
                .build();
        return exchange.mutate().request(mutated).build();
    }


    private Mono<Void> writeError(ServerWebExchange exchange, AuthException ex) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(ex.getStatus());
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("timestamp", Instant.now().toString());
        body.put("path", exchange.getRequest().getPath().toString());
        body.put("status", ex.getStatus().value());
        body.put("error", ex.getStatus().getReasonPhrase());
        body.put("message", ex.getMessage());

        return response.writeWith(
                jsonEncoder.encode(
                        Mono.just(body),
                        response.bufferFactory(),
                        ResolvableType.forClassWithGenerics(Map.class, String.class, Object.class),
                        MediaType.APPLICATION_JSON,
                        null
                )
        );
    }


    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }
}
