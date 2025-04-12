package ru.zeker.userservice.domain.dto;

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
    @Size(max = 512, message = "Refresh token must be between 512 characters long")
    @NotBlank(message = "Refresh token cannot be empty")
    private String refreshToken;
}
