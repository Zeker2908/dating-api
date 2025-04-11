package ru.zeker.user_service.exception;

import org.springframework.http.HttpStatus;
import ru.zeker.common.exception.ApiException;

public class TokenNotFoundException extends ApiException {
    public TokenNotFoundException(String message) {
        super(message, HttpStatus.NOT_FOUND);
    }
    public TokenNotFoundException() {
        super("Token not found", HttpStatus.NOT_FOUND);
    }
}
