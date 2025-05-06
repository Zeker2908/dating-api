package ru.zeker.authenticationservice.domain.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@Schema(description = "Запрос на повторную отправку письма подтверждения email")
public class ResendVerificationRequest {

    @Schema(description = "Email пользователя", example = "user@example.com", required = true)
    @Email
    @NotBlank
    @Size(min = 8, max = 255, message = "Длина почты должна быть от 8 до 255 символов")
    private String email;
}