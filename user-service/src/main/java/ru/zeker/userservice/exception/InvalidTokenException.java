package ru.zeker.userservice.exception;

import org.springframework.http.HttpStatus;
import ru.zeker.common.exception.ApiException;

public class InvalidTokenException extends ApiException {
    public InvalidTokenException(String message) {
        super(message, HttpStatus.UNAUTHORIZED);
    }
    public InvalidTokenException() {
        super("Недействительный токен", HttpStatus.UNAUTHORIZED);
    }
}
