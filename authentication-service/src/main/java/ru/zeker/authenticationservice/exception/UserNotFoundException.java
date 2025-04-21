package ru.zeker.authenticationservice.exception;

import org.springframework.http.HttpStatus;
import ru.zeker.common.exception.ApiException;

public class UserNotFoundException extends ApiException {
    public UserNotFoundException(String message) {
        super(message, HttpStatus.NOT_FOUND);
    }
    public UserNotFoundException() {
        super("Пользователь не найден", HttpStatus.NOT_FOUND);
    }
}
