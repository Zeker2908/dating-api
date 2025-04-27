package ru.zeker.apigateway.exception;

import org.springframework.http.HttpStatus;
import ru.zeker.common.exception.ApiException;

public class AuthException extends ApiException {
    public AuthException(String message, HttpStatus status) {
        super(message, status);
    }
}
