package ru.zeker.user_service.controller;

import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import jakarta.ws.rs.core.HttpHeaders;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import ru.zeker.user_service.domain.dto.AuthenticationResponse;
import ru.zeker.user_service.domain.dto.LoginRequest;
import ru.zeker.user_service.domain.dto.RegisterRequest;
import ru.zeker.user_service.domain.dto.Tokens;
import ru.zeker.user_service.service.AuthenticationService;
import ru.zeker.user_service.service.RefreshTokenService;

import java.time.Duration;

@RestController
@RequestMapping("/api/v1/auth") //TODO: Убрать приписку api/v1, добавив Strip prefix в конфигурацию Gateway
@RequiredArgsConstructor
public class AuthenticationController {
    private final AuthenticationService authenticationService;
    private final RefreshTokenService refreshTokenService;

    //TODO: Добавить подтвержение почты
    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody @Valid RegisterRequest request,
                                                           HttpServletResponse response){
        Tokens tokens = authenticationService.register(request);
        ResponseCookie cookie = setRefreshTokenCookie(tokens.getRefreshToken(), Duration.ofDays(7));
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
        return ResponseEntity.ok(new AuthenticationResponse(tokens.getToken()));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> login(@RequestBody @Valid LoginRequest request,
                                                        HttpServletResponse response){
        Tokens tokens = authenticationService.login(request);
        ResponseCookie cookie = setRefreshTokenCookie(tokens.getRefreshToken(), Duration.ofDays(7));
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
        return ResponseEntity.ok(new AuthenticationResponse(tokens.getToken()));
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthenticationResponse> refreshToken(@CookieValue(name = "refresh_token") String refreshToken,
                                                               HttpServletResponse response){
        Tokens tokens = authenticationService.refreshToken(refreshToken);
        ResponseCookie cookie = setRefreshTokenCookie(tokens.getRefreshToken(), Duration.ofDays(7));
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
        return ResponseEntity.ok(new AuthenticationResponse(tokens.getToken()));
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(@CookieValue(name = "refresh_token") String refreshToken, HttpServletResponse response){
        refreshTokenService.revokeRefreshToken(refreshToken);
        ResponseCookie cookie = setRefreshTokenCookie("", Duration.ZERO);
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
        return ResponseEntity.noContent().build();
    }

    private ResponseCookie setRefreshTokenCookie(String value, Duration duration) {
        return ResponseCookie.from("refresh_token", value)
                .httpOnly(true)
                .secure(true)
                .path("/api")
                .maxAge(duration)
                .sameSite("Strict")
                .build();
    }
}
