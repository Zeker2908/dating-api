package ru.zeker.user_service.exception;

import org.springframework.http.HttpStatus;
import ru.zeker.common.exception.ApiException;

public class RefreshTokenExpiredException extends ApiException {
    public RefreshTokenExpiredException(String message) {
        super(message, HttpStatus.UNAUTHORIZED);
    }
    public RefreshTokenExpiredException() {
        super("Refresh token expired", HttpStatus.UNAUTHORIZED);
    }
}
