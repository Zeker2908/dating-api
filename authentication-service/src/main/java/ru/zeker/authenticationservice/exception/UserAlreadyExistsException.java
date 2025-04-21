package ru.zeker.authenticationservice.exception;

import org.springframework.http.HttpStatus;
import ru.zeker.common.exception.ApiException;

public class UserAlreadyExistsException extends ApiException {
    public UserAlreadyExistsException(String message) {
        super(message, HttpStatus.CONFLICT);
    }
    public UserAlreadyExistsException() {
        super("Пользователь уже зарегистрирован", HttpStatus.CONFLICT);
    }
}
