package ru.zeker.authenticationservice.util;

import org.springframework.http.ResponseCookie;

import java.time.Duration;

public final class CookieUtils {
    private CookieUtils() {}

    public static ResponseCookie createRefreshTokenCookie(String value, Duration duration) {
        return ResponseCookie.from("refresh_token", value)
                .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge(duration)
                .sameSite("Strict")
                .build();
    }
}