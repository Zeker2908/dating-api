package ru.zeker.authenticationservice.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.ws.rs.core.HttpHeaders;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import ru.zeker.authenticationservice.domain.dto.Tokens;
import ru.zeker.authenticationservice.domain.dto.request.*;
import ru.zeker.authenticationservice.domain.dto.response.AuthenticationResponse;
import ru.zeker.authenticationservice.service.AuthenticationService;
import ru.zeker.authenticationservice.service.RefreshTokenService;

import java.time.Duration;

import static ru.zeker.authenticationservice.util.CookieUtils.createRefreshTokenCookie;

/**
 * Контроллер для управления аутентификацией и авторизацией пользователей.
 * Обеспечивает регистрацию, вход в систему, управление токенами доступа,
 * восстановление пароля и подтверждение email.
 */
@Validated
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Tag(name = "Аутентификация", description = "Управление пользователями: регистрация, вход, email подтверждение и восстановление пароля")
public class AuthenticationController {
    private final AuthenticationService authenticationService;
    private final RefreshTokenService refreshTokenService;

    /**
     * Регистрирует нового пользователя с отправкой подтверждения по email.
     *
     * @param request {@link RegisterRequest} - данные для регистрации
     * @return {@link ResponseEntity} с HTTP-статусом 201 (Created)
     * @throws jakarta.validation.ConstraintViolationException если данные запроса невалидны
     */
    @Operation(summary = "Регистрация нового пользователя", description = "Создает пользователя и отправляет письмо с подтверждением на email")
    @ApiResponses({
            @ApiResponse(responseCode = "201", description = "Пользователь успешно зарегистрирован"),
            @ApiResponse(responseCode = "409", description = "Пользователь уже существует ")
    })
    @PostMapping("/register")
    public ResponseEntity<Void> signup(@RequestBody @Valid RegisterRequest request) {
        authenticationService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    /**
     * Аутентифицирует пользователя и выдает токены доступа.
     *
     * @param request {@link LoginRequest} - учетные данные пользователя
     * @param response {@link HttpServletResponse} для установки refresh token в cookie
     * @return {@link ResponseEntity} с {@link AuthenticationResponse} (access token)
     * @throws jakarta.validation.ConstraintViolationException если данные запроса невалидны
     * @throws org.springframework.security.authentication.BadCredentialsException если учетные данные неверны
     */
    @Operation(summary = "Вход в систему", description = "Аутентификация пользователя и установка refresh токена в cookie")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Успешная аутентификация",
                    content = @Content(schema = @Schema(implementation = AuthenticationResponse.class))),
            @ApiResponse(responseCode = "401", description = "Неверные учетные данные")
    })
    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> login(
            @RequestBody @Valid LoginRequest request,
            HttpServletResponse response) {
        Tokens tokens = authenticationService.login(request);
        ResponseCookie cookie = createRefreshTokenCookie(tokens.getRefreshToken(), Duration.ofDays(7));
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
        return ResponseEntity.ok(new AuthenticationResponse(tokens.getToken()));
    }

    /**
     * Подтверждает email пользователя по токену подтверждения.
     *
     * @param request {@link ConfirmationEmailRequest} - токен подтверждения
     * @return {@link ResponseEntity} с HTTP-статусом 200 (OK)
     * @throws jakarta.validation.ConstraintViolationException если токен невалиден
     * @throws ru.zeker.authenticationservice.exception.TokenExpiredException если токен просрочен
     */
    @Operation(summary = "Подтверждение email", description = "Подтверждает email по предоставленному токену")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Email успешно подтвержден"),
            @ApiResponse(responseCode = "400", description = "Неверный токен")
    })
    @PatchMapping("/email/verify")
    public ResponseEntity<Void> confirmEmail(@RequestBody @Valid ConfirmationEmailRequest request) {
        authenticationService.confirmEmail(request);
        return ResponseEntity.ok().build();
    }

    /**
     * Повторно отправляет письмо с подтверждением email.
     *
     * @param request {@link ResendVerificationRequest} - email пользователя
     * @return {@link ResponseEntity} с HTTP-статусом 202 (Accepted)
     * @throws jakarta.validation.ConstraintViolationException если email невалиден
     */
    @Operation(summary = "Повторная отправка подтверждения", description = "Отправляет письмо подтверждения, если оно не было подтверждено ранее")
    @ApiResponses({
            @ApiResponse(responseCode = "202", description = "Письмо отправлено"),
            @ApiResponse(responseCode = "429", description = "Письмо уже отправлено, повторная отправка через 60 секунд")
    })
    @PostMapping("/email/resend-verification")
    public ResponseEntity<Void> resendConfirmationEmail(
            @RequestBody @Valid ResendVerificationRequest request) {
        authenticationService.resendVerificationEmail(request);
        return ResponseEntity.accepted().build();
    }

    /**
     * Инициирует процесс восстановления пароля.
     *
     * @param request {@link UserUpdateRequest} - email пользователя
     * @return {@link ResponseEntity} с HTTP-статусом 202 (Accepted)
     * @throws jakarta.validation.ConstraintViolationException если email невалиден
     */
    @Operation(summary = "Запрос на сброс пароля", description = "Отправляет email с ссылкой на восстановление пароля")
    @ApiResponse(responseCode = "202", description = "Письмо для сброса отправлено")
    @PostMapping("/password/reset-request")
    public ResponseEntity<Void> forgotPassword(@RequestBody @Valid UserUpdateRequest request) {
        authenticationService.forgotPassword(request);
        return ResponseEntity.accepted().build();
    }


    /**
     * Сбрасывает пароль пользователя по токену восстановления.
     *
     * @param request {@link ResetPasswordRequest} - новый пароль и токен
     * @return {@link ResponseEntity} с HTTP-статусом 200 (OK)
     * @throws jakarta.validation.ConstraintViolationException если данные запроса невалидны
     * @throws ru.zeker.authenticationservice.exception.TokenExpiredException если токен просрочен
     */
    @Operation(summary = "Сброс пароля", description = "Сбрасывает пароль по токену восстановления")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Пароль успешно сброшен"),
            @ApiResponse(responseCode = "400", description = "Недействительный или просроченный токен", content = @Content)
    })
    @PatchMapping("/password")
    public ResponseEntity<Void> resetPassword(@RequestBody @Valid ResetPasswordRequest request) {
        authenticationService.resetPassword(request);
        return ResponseEntity.ok().build();
    }

    /**
     * Обновляет access token по refresh token.
     *
     * @param refreshToken refresh token из cookie
     * @param response {@link HttpServletResponse} для установки нового refresh token
     * @return {@link ResponseEntity} с новым {@link AuthenticationResponse} (access token)
     * @throws jakarta.validation.ConstraintViolationException если refresh token невалиден
     * @throws ru.zeker.authenticationservice.exception.TokenExpiredException если refresh token просрочен
     */
    @Operation(summary = "Обновление access token", description = "Обновляет access token по refresh token из cookie и возвращает новый access token")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Токен успешно обновлен",
                    content = @Content(schema = @Schema(implementation = AuthenticationResponse.class))),
            @ApiResponse(responseCode = "401", description = "Невалидный или просроченный refresh token", content = @Content)
    })
    @PostMapping("/token/refresh")
    public ResponseEntity<AuthenticationResponse> refreshToken(
            @CookieValue(name = "refresh_token") @NotBlank String refreshToken,
            HttpServletResponse response) {
        Tokens tokens = authenticationService.refreshToken(refreshToken);
        ResponseCookie cookie = createRefreshTokenCookie(tokens.getRefreshToken(), Duration.ofDays(7));
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
        return ResponseEntity.ok(new AuthenticationResponse(tokens.getToken()));
    }

    /**
     * Выходит пользователя из текущей сессии.
     *
     * @param refreshToken refresh token из cookie
     * @param response {@link HttpServletResponse} для очистки cookie
     * @return {@link ResponseEntity} с HTTP-статусом 204 (No Content)
     * @throws jakarta.validation.ConstraintViolationException если refresh token невалиден
     */
    @Operation(summary = "Выход из текущей сессии", description = "Удаляет текущий refresh token и очищает cookie")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Выход выполнен"),
            @ApiResponse(responseCode = "400", description = "Невалидный refresh token", content = @Content)
    })
    @DeleteMapping("/sessions/current")
    public ResponseEntity<Void> logout(
            @CookieValue(name = "refresh_token") @NotBlank String refreshToken,
            HttpServletResponse response) {
        refreshTokenService.revokeRefreshToken(refreshToken);
        ResponseCookie cookie = createRefreshTokenCookie("", Duration.ZERO);
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
        return ResponseEntity.noContent().build();
    }

    /**
     * Выходит пользователя из всех активных сессий.
     *
     * @param refreshToken refresh token из cookie
     * @param response {@link HttpServletResponse} для очистки cookie
     * @return {@link ResponseEntity} с HTTP-статусом 204 (No Content)
     * @throws jakarta.validation.ConstraintViolationException если refresh token невалиден
     */
    @Operation(summary = "Выход со всех устройств", description = "Удаляет все refresh токены пользователя и очищает cookie")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Все сессии завершены"),
            @ApiResponse(responseCode = "400", description = "Невалидный refresh token", content = @Content)
    })
    @DeleteMapping("/sessions")
    public ResponseEntity<Void> revokeAllRefreshTokens(
            @CookieValue(name = "refresh_token") @NotBlank String refreshToken,
            HttpServletResponse response) {
        refreshTokenService.revokeAllUserTokens(refreshToken);
        ResponseCookie cookie = createRefreshTokenCookie("", Duration.ZERO);
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
        return ResponseEntity.noContent().build();
    }
}
