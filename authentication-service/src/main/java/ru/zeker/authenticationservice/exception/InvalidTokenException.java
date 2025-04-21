package ru.zeker.authenticationservice.exception;

import org.springframework.http.HttpStatus;
import ru.zeker.common.exception.ApiException;

public class InvalidTokenException extends ApiException {
  public InvalidTokenException(String message) {
    super(message, HttpStatus.BAD_REQUEST);
  }
  public InvalidTokenException() {
    super("Токен недействителен", HttpStatus.BAD_REQUEST);
  }
}
