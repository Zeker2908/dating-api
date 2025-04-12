package ru.zeker.userservice.controller;

import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import jakarta.ws.rs.core.HttpHeaders;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import ru.zeker.userservice.domain.dto.AuthenticationResponse;
import ru.zeker.userservice.domain.dto.LoginRequest;
import ru.zeker.userservice.domain.dto.RegisterRequest;
import ru.zeker.userservice.domain.dto.Tokens;
import ru.zeker.userservice.service.AuthenticationService;
import ru.zeker.userservice.service.RefreshTokenService;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

/**
 * Контроллер для управления аутентификацией пользователей
 */
@Slf4j
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    private final AuthenticationService authenticationService;
    private final RefreshTokenService refreshTokenService;

    /**
     * Регистрация нового пользователя с отправкой подтверждения по email через Kafka
     *
     * @param request данные для регистрации
     * @return сообщение о статусе операции
     */
    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public ResponseEntity<Map<String, String>> registerWithKafka(@RequestBody @Valid RegisterRequest request) {
        log.info("Запрос на регистрацию пользователя: {}", request.getEmail());
        authenticationService.register(request);
        
        Map<String, String> response = new HashMap<>();
        response.put("message", "Письмо с подтверждением отправлено на ваш email");
        response.put("status", "success");
        
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * Аутентификация пользователя
     *
     * @param request данные для входа
     * @param response HTTP-ответ для установки cookie
     * @return токен доступа
     */
    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> login(@RequestBody @Valid LoginRequest request,
                                                        HttpServletResponse response) {
        log.info("Запрос на вход пользователя: {}", request.getEmail());
        Tokens tokens = authenticationService.login(request);
        ResponseCookie cookie = createRefreshTokenCookie(tokens.getRefreshToken(), Duration.ofDays(7));
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
        
        return ResponseEntity.ok(new AuthenticationResponse(tokens.getToken()));
    }

    /**
     * Подтверждение email пользователя
     *
     * @param token токен подтверждения
     * @return сообщение о статусе операции
     */
    @PostMapping("/confirm")
    public ResponseEntity<Map<String, String>> confirmEmail(@RequestParam @NotNull String token) {
        log.info("Запрос на подтверждение email");
        authenticationService.confirmEmail(token);
        
        Map<String, String> response = new HashMap<>();
        response.put("message", "Email успешно подтвержден");
        response.put("status", "success");
        
        return ResponseEntity.ok(response);
    }

    /**
     * Обновление токена доступа
     *
     * @param refreshToken токен обновления из cookie
     * @param response HTTP-ответ для установки обновленного cookie
     * @return новый токен доступа
     */
    @PostMapping("/refresh")
    public ResponseEntity<AuthenticationResponse> refreshToken(@CookieValue(name = "refresh_token") @NotNull String refreshToken,
                                                               HttpServletResponse response) {
        log.debug("Запрос на обновление токена");
        Tokens tokens = authenticationService.refreshToken(refreshToken);
        ResponseCookie cookie = createRefreshTokenCookie(tokens.getRefreshToken(), Duration.ofDays(7));
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
        
        return ResponseEntity.ok(new AuthenticationResponse(tokens.getToken()));
    }

    /**
     * Выход пользователя из системы
     *
     * @param refreshToken токен обновления из cookie
     * @param response HTTP-ответ для очистки cookie
     * @return статус операции
     */
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@CookieValue(name = "refresh_token", required = false) String refreshToken, 
                                       HttpServletResponse response) {
        log.info("Запрос на выход из системы");
        
        if (refreshToken != null && !refreshToken.isEmpty()) {
            refreshTokenService.revokeRefreshToken(refreshToken);
        }
        
        ResponseCookie cookie = createRefreshTokenCookie("", Duration.ZERO);
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
        
        return ResponseEntity.noContent().build();
    }

    /**
     * Создает cookie для refresh-токена с заданными параметрами
     *
     * @param value значение токена
     * @param duration срок действия
     * @return cookie с токеном обновления
     */
    private ResponseCookie createRefreshTokenCookie(String value, Duration duration) {
        return ResponseCookie.from("refresh_token", value)
                .httpOnly(true)
                .secure(true)
                .path("/api")
                .maxAge(duration)
                .sameSite("Strict")
                .build();
    }
}
