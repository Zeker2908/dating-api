<<<<<<< HEAD:user-service/src/main/java/ru/zeker/userservice/exception/InvalidTokenException.java
package ru.zeker.userservice.exception;
=======
package ru.zeker.user_service.exception;
>>>>>>> origin/main:user-service/src/main/java/ru/zeker/user_service/exception/InvalidTokenException.java

import org.springframework.http.HttpStatus;
import ru.zeker.common.exception.ApiException;

public class InvalidTokenException extends ApiException {
    public InvalidTokenException(String message) {
        super(message, HttpStatus.UNAUTHORIZED);
    }
    public InvalidTokenException() {
<<<<<<< HEAD:user-service/src/main/java/ru/zeker/userservice/exception/InvalidTokenException.java
        super("Недействительный токен", HttpStatus.UNAUTHORIZED);
=======
        super("Invalid token", HttpStatus.UNAUTHORIZED);
>>>>>>> origin/main:user-service/src/main/java/ru/zeker/user_service/exception/InvalidTokenException.java
    }
}
