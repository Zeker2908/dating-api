package ru.zeker.authenticationservice.domain.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class RefreshTokenRequest {
    @Size(max = 512, message = "Длина токена обновления должна составлять 512 символов.")
    @NotBlank(message = "Токен обновления не может быть пустым")
    private String refreshToken;
}
