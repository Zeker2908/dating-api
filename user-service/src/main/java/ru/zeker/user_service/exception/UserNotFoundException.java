package ru.zeker.user_service.exception;

import org.springframework.http.HttpStatus;

public class UserNotFoundException extends ApiException {
    public UserNotFoundException(String message, HttpStatus status) {
        super(message, status);
    }
    public UserNotFoundException() {
        super("User not found", HttpStatus.NOT_FOUND);
    }
}
