package ru.zeker.user_service.exception;

import org.springframework.http.HttpStatus;
import ru.zeker.common.exception.ApiException;

public class VerificationTokenNotFoundException extends ApiException {
    public VerificationTokenNotFoundException() {
        super("Verification token not found", HttpStatus.NOT_FOUND);
    }
    public VerificationTokenNotFoundException(String message) {
        super(message, HttpStatus.NOT_FOUND);
    }
}
