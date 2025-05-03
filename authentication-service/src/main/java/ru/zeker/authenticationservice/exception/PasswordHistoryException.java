package ru.zeker.authenticationservice.exception;

import org.springframework.http.HttpStatus;
import ru.zeker.common.exception.ApiException;

public class PasswordHistoryException extends ApiException {
    public PasswordHistoryException(String message) {
        super(message, HttpStatus.BAD_REQUEST);
    }
    public PasswordHistoryException(){
        super("Некорректный пароль", HttpStatus.BAD_REQUEST );
    }
}
