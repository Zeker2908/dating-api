package ru.zeker.authenticationservice.domain.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ConfirmationEmailRequest {
    @NotBlank
    private String token;
}
