package ru.zeker.authenticationservice.domain.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ResendVerificationRequest {
    @Email
    @NotBlank
    @Size(min = 8, max = 255, message = "Длина почты должна быть от 8 до 255 символов")
    private String email;
}
