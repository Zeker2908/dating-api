package ru.zeker.authenticationservice.exception;

import org.springframework.http.HttpStatus;
import ru.zeker.common.exception.ApiException;

public class OAuth2ProviderException extends ApiException {
    public OAuth2ProviderException(String message) {
        super(message, HttpStatus.BAD_REQUEST);
    }
    public OAuth2ProviderException() {
        super("Произошла ошибка в OAuth2 провайдере", HttpStatus.BAD_REQUEST);
    }
}
