package ru.zeker.user_service.exception;

import org.springframework.http.HttpStatus;

public class RefreshTokenNotFoundException extends ApiException {
    public RefreshTokenNotFoundException(String message, HttpStatus status) {
        super(message, status);
    }
    public RefreshTokenNotFoundException() {
        super("Refresh token not found", HttpStatus.NOT_FOUND);
    }
}
