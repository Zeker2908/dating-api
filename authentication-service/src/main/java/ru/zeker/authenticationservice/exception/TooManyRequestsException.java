package ru.zeker.authenticationservice.exception;

import org.springframework.http.HttpStatus;
import ru.zeker.common.exception.ApiException;

public class TooManyRequestsException extends ApiException {
    public TooManyRequestsException(String message) {
        super(message, HttpStatus.TOO_MANY_REQUESTS);
    }
    public TooManyRequestsException() {
        super("Слишком много запросов", HttpStatus.TOO_MANY_REQUESTS);
    }
}
