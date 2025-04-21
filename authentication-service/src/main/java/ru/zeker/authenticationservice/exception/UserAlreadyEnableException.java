package ru.zeker.authenticationservice.exception;

import org.springframework.http.HttpStatus;
import ru.zeker.common.exception.ApiException;

public class UserAlreadyEnableException extends ApiException {
    public UserAlreadyEnableException(String message) {
        super(message, HttpStatus.CONFLICT);
    }
    public UserAlreadyEnableException() {
        super("Пользователь уже активирован", HttpStatus.CONFLICT);
    }
}
