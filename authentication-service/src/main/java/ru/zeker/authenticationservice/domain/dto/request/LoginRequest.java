package ru.zeker.authenticationservice.domain.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Schema(description = "Запрос на аутентификацию пользователя")
public class LoginRequest {

    @Schema(description = "Email пользователя", example = "user@example.com", required = true)
    @NotBlank(message = "Адрес электронной почты не может быть пустым")
    @Email(message = "Адрес электронной почты должен быть в формате user@example.com")
    @Size(min = 5, max = 255, message = "Адрес электронной почты должен содержать от 5 до 255 символов")
    private String email;

    @Schema(description = "Пароль пользователя", example = "P@ssw0rd123", required = true)
    @NotBlank(message = "Пароль не может быть пустым")
    @Size(max = 255, message = "Длина пароля должна быть до 255 символов")
    private String password;
}
