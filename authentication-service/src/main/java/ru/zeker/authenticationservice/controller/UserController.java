package ru.zeker.authenticationservice.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.ws.rs.core.HttpHeaders;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import ru.zeker.authenticationservice.domain.dto.request.BindPasswordRequest;
import ru.zeker.authenticationservice.domain.dto.request.ChangePasswordRequest;
import ru.zeker.authenticationservice.domain.dto.response.UserResponse;
import ru.zeker.authenticationservice.domain.mapper.UserMapper;
import ru.zeker.authenticationservice.service.RefreshTokenService;
import ru.zeker.authenticationservice.service.UserService;

import java.time.Duration;
import java.util.UUID;

import static ru.zeker.authenticationservice.util.CookieUtils.createRefreshTokenCookie;
import static ru.zeker.common.headers.ApiHeaders.USER_ID;

/**
 * Контроллер для управления пользователями и их аутентификационными данными.
 * Обеспечивает операции получения информации о пользователе, управления паролями и удаления аккаунта.
 */
@Validated
@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
@Tag(name = "User Management", description = "API для управления пользователями и их аутентификационными данными")
public class UserController {
    private final UserService userService;
    private final UserMapper userMapper;
    private final RefreshTokenService refreshTokenService;

    /**
     * Получает информацию о текущем аутентифицированном пользователе.
     *
     * @param id ID пользователя, передаваемое в заголовке запроса (обязательное, не пустое)
     * @return {@link ResponseEntity} с данными пользователя в формате {@link UserResponse}
     * @throws jakarta.validation.ConstraintViolationException если ID пустой или невалидный
     */
    @Operation(
            summary = "Получить информацию о пользователе",
            description = "Возвращает данные текущего аутентифицированного пользователя",
            responses = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Успешное получение данных пользователя",
                            content = @Content(schema = @Schema(implementation = UserResponse.class)))
                            }
                    )
    @GetMapping("/me")
    public ResponseEntity<UserResponse> getCurrentUser(
            @Parameter(description = "ID пользователя", required = true, example = "550e8400-e29b-41d4-a716-446655440000")
            @RequestHeader(USER_ID) @NotBlank String id) {
        return ResponseEntity.ok(userMapper.toResponse(userService.findById(UUID.fromString(id))));
    }

    /**
     * Привязывает пароль к учетной записи пользователя.
     *
     * @param id ID пользователя, передаваемое в заголовке запроса (обязательное, не пустое)
     * @param request {@link BindPasswordRequest} с данными для привязки пароля
     * @return {@link ResponseEntity} с кодом 202 (Accepted)
     * @throws jakarta.validation.ConstraintViolationException если ID или данные запроса невалидны
     */
    @Operation(
            summary = "Привязать пароль",
            description = "Привязывает пароль к учетной записи пользователя",
            responses = {
                    @ApiResponse(responseCode = "202", description = "Запрос на привязку пароля принят"),
                    @ApiResponse(responseCode = "400", description = "Неверные входные данные"),
                    @ApiResponse(responseCode = "409", description = "Пароль уже привязан")
            }
    )
    @PutMapping("/me/password")
    public ResponseEntity<Void> bindPassword(
            @Parameter(description = "ID пользователя", required = true, example = "550e8400-e29b-41d4-a716-446655440000")
            @RequestHeader(USER_ID) @NotBlank String id,

            @Parameter(description = "Данные для привязки пароля", required = true)
            @RequestBody @Valid BindPasswordRequest request) {
        userService.bindPassword(id, request);
        return ResponseEntity.accepted().build();
    }

    /**
     * Изменяет пароль пользователя и выполняет выход из всех устройств.
     *
     * @param id ID пользователя, передаваемое в заголовке запроса (обязательное, не пустое)
     * @param changerPasswordRequest {@link ChangePasswordRequest} с текущим и новым паролем
     * @param refreshToken refresh token из куки (обязательный, не пустой)
     * @param response {@link HttpServletResponse} для очистки куки
     * @return {@link ResponseEntity} с кодом 204 (No Content)
     * @throws jakarta.validation.ConstraintViolationException если параметры невалидны
     */
    @Operation(
            summary = "Изменить пароль",
            description = "Изменяет пароль пользователя и выполняет выход из всех устройств",
            responses = {
                    @ApiResponse(responseCode = "204", description = "Пароль успешно изменен"),
                    @ApiResponse(responseCode = "400", description = "Неверные входные данные"),
                    @ApiResponse(responseCode = "401", description = "Неверный текущий пароль")
            }
    )
    @PatchMapping("/me/password")
    public ResponseEntity<Void> changePassword(
            @Parameter(description = "ID пользователя", required = true, example = "550e8400-e29b-41d4-a716-446655440000")
            @RequestHeader(USER_ID) @NotBlank String id,

            @Parameter(description = "Текущий и новый пароль", required = true)
            @RequestBody @Valid ChangePasswordRequest changerPasswordRequest,

            @Parameter(description = "Refresh token из куки", required = true)
            @CookieValue(name = "refresh_token") @NotBlank String refreshToken,

            HttpServletResponse response) {
        userService.changePassword(id, changerPasswordRequest.getOldPassword(), changerPasswordRequest.getNewPassword());
        revokeTokenAndClearCookie(refreshToken, response);
        return ResponseEntity.noContent().build();
    }

    @Operation(
            summary = "Удалить аккаунт",
            description = "Удаляет учетную запись пользователя и выполняет выход из всех устройств",
            responses = {
                    @ApiResponse(responseCode = "204", description = "Аккаунт успешно удален"),
                    @ApiResponse(responseCode = "400", description = "Неверный ID пользователя")
            }
    )
    @DeleteMapping("/me")
    public ResponseEntity<Void> deleteCurrentUser(
            @Parameter(description = "ID пользователя", required = true, example = "550e8400-e29b-41d4-a716-446655440000")
            @RequestHeader(USER_ID) @NotBlank String id,

            @Parameter(description = "Refresh token из куки")
            @CookieValue(name = "refresh_token") String refreshToken,

            HttpServletResponse response) {
        userService.deleteById(UUID.fromString(id));
        revokeTokenAndClearCookie(refreshToken, response);
        return ResponseEntity.noContent().build();
    }

    private void revokeTokenAndClearCookie(String refreshToken, HttpServletResponse response) {
        refreshTokenService.revokeAllUserTokens(refreshToken);
        response.addHeader(HttpHeaders.SET_COOKIE,
                createRefreshTokenCookie("", Duration.ZERO).toString());
    }
}