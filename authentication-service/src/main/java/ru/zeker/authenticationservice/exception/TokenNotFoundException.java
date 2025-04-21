package ru.zeker.authenticationservice.exception;

import org.springframework.http.HttpStatus;
import ru.zeker.common.exception.ApiException;

public class TokenNotFoundException extends ApiException {
    public TokenNotFoundException(String message) {
        super(message, HttpStatus.NOT_FOUND);
    }
    public TokenNotFoundException() {
        super("Токен не найден", HttpStatus.NOT_FOUND);
    }
}
