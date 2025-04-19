package ru.zeker.userservice.exception;

import org.springframework.http.HttpStatus;
import ru.zeker.common.exception.ApiException;

public class EmailNotVerifiedException extends ApiException {
    public EmailNotVerifiedException(String message) {
        super(message, HttpStatus.BAD_REQUEST);
    }
    public EmailNotVerifiedException() {
        super("Email не верифицирован", HttpStatus.BAD_REQUEST);
    }
}
