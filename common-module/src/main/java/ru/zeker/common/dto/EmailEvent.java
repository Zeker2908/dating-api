package ru.zeker.common.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.*;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class EmailEvent {
    @NotNull
    private EmailEventType type;

    @NotBlank
    private String id;

    @NotBlank
    @Email
    private String email;

    @NotBlank
    private String token;

    @NotBlank
    private String firstName;
}
