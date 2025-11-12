package ru.zeker.authenticationservice.domain.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Schema(description = "Запрос на изменение пароля")
public class ChangePasswordRequest {

    @NotBlank
    @Schema(description = "Текущий пароль", example = "OldPass123!")
    private String oldPassword;

    @NotBlank(message = "Пароль не может быть пустым")
    @Size(min = 8, max = 255, message = "Длина пароля должна быть от 8 до 255 символов")
    @Pattern(
            regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[^A-Za-z\\d]).{8,255}$",
            message = "Пароль должен содержать заглавную, строчную букву, цифру и спецсимвол"
    )
    @Schema(
            description = "Новый пароль. Должен содержать заглавную, строчную букву, цифру и спецсимвол",
            example = "NewPass123!",
            minLength = 8,
            maxLength = 255
    )
    private String newPassword;
}