package ru.zeker.authenticationservice.controller;

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
    @GetMapping("/me")
    public ResponseEntity<UserResponse> getCurrentUser(
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
    @PutMapping("/me/password")
    public ResponseEntity<Void> bindPassword(
            @RequestHeader(USER_ID) @NotBlank String id,
            @RequestBody @Valid BindPasswordRequest request)
    {
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
    @PatchMapping("/me/password")
    public ResponseEntity<Void> changePassword(
            @RequestHeader(USER_ID) @NotBlank String id,
            @RequestBody @Valid ChangePasswordRequest changerPasswordRequest,
            @CookieValue(name = "refresh_token") @NotBlank String refreshToken,
            HttpServletResponse response)
    {
        userService.changePassword(id, changerPasswordRequest.getOldPassword(), changerPasswordRequest.getNewPassword());
        revokeTokenAndClearCookie(refreshToken, response);
        return ResponseEntity.noContent().build();
    }

    /**
     * Удаляет учетную запись текущего пользователя и выполняет выход из всех устройств.
     *
     * @param id ID пользователя, передаваемое в заголовке запроса (обязательное, не пустое)
     * @param refreshToken refresh token из куки
     * @param response {@link HttpServletResponse} для очистки куки
     * @return {@link ResponseEntity} с кодом 204 (No Content)
     * @throws jakarta.validation.ConstraintViolationException если ID невалиден
     */
    @DeleteMapping("/me")
    public ResponseEntity<Void> deleteCurrentUser(
            @RequestHeader(USER_ID) @NotBlank String id,
            @CookieValue(name = "refresh_token") String refreshToken,
            HttpServletResponse response)
    {
        userService.deleteById(UUID.fromString(id));
        revokeTokenAndClearCookie(refreshToken, response);
        return ResponseEntity.noContent().build();
    }


    /**
     * Отзывает все refresh tokens пользователя и очищает куку.
     *
     * @param refreshToken refresh token для отзыва
     * @param response {@link HttpServletResponse} для установки пустой куки
     */
    private void revokeTokenAndClearCookie(String refreshToken, HttpServletResponse response) {
        refreshTokenService.revokeAllUserTokens(refreshToken);
        response.addHeader(HttpHeaders.SET_COOKIE,
                createRefreshTokenCookie("", Duration.ZERO).toString());
    }
}