package ru.zeker.common.dto.kafka;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.*;

import java.util.Map;

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

    @NotNull
    private Map<String, String> payload;

}
