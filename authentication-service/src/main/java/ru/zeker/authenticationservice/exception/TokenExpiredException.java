package ru.zeker.authenticationservice.exception;

import org.springframework.http.HttpStatus;
import ru.zeker.common.exception.ApiException;

public class TokenExpiredException extends ApiException {
    public TokenExpiredException(String message) {
        super(message, HttpStatus.UNAUTHORIZED);
    }
    public TokenExpiredException() {
        super("Токен истек", HttpStatus.UNAUTHORIZED);
    }
}
