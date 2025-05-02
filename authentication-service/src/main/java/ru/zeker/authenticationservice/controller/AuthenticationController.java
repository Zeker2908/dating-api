package ru.zeker.authenticationservice.controller;

import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import jakarta.ws.rs.core.HttpHeaders;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import ru.zeker.authenticationservice.domain.dto.Tokens;
import ru.zeker.authenticationservice.domain.dto.request.*;
import ru.zeker.authenticationservice.domain.dto.response.AuthenticationResponse;
import ru.zeker.authenticationservice.service.AuthenticationService;
import ru.zeker.authenticationservice.service.RefreshTokenService;

import java.time.Duration;

import static ru.zeker.authenticationservice.util.CookieUtils.createRefreshTokenCookie;

/**
 * Контроллер для управления аутентификацией пользователей
 */
@Slf4j
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    private final AuthenticationService authenticationService;
    private final RefreshTokenService refreshTokenService;

    /**
     * Регистрация нового пользователя с отправкой подтверждения по email через Kafka
     *
     * @param request данные для регистрации
     * @return сообщение о статусе операции
     */
    @PostMapping("/register")
    public ResponseEntity<Void> registerWithKafka(@RequestBody @Valid RegisterRequest request) {
        authenticationService.register(request);

        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    /**
     * Аутентификация пользователя
     *
     * @param request данные для входа
     * @param response HTTP-ответ для установки cookie
     * @return токен доступа
     */
    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> login(@RequestBody @Valid LoginRequest request,
                                                        HttpServletResponse response) {
        Tokens tokens = authenticationService.login(request);
        ResponseCookie cookie = createRefreshTokenCookie(tokens.getRefreshToken(), Duration.ofDays(7));
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());

        return ResponseEntity.ok(new AuthenticationResponse(tokens.getToken()));
    }

    /**
     * Подтверждение email пользователя
     *
     * @param request токен
     * @return сообщение о статусе операции
     */
    @PostMapping("/email-confirmation")
    public ResponseEntity<Void> confirmEmail(@RequestBody @Valid ConfirmationEmailRequest request) {
        authenticationService.confirmEmail(request);

        return ResponseEntity.ok().build();
    }

    /**
     * Обрабатывает запрос на повторную отправку подтверждения email.
     *
     * <p>Этот метод принимает POST-запрос с телом, содержащим объект {@link ResendVerificationRequest},
     * который содержит информацию, необходимую для повторной отправки подтверждения email.
     * Метод вызывает сервис аутентификации для выполнения этой операции и возвращает ответ с кодом состояния 202 Accepted.</p>
     *
     * @param request объект запроса, содержащий информацию для повторной отправки подтверждения email.
     * @return {@code ResponseEntity<Void>} с кодом состояния 202 Accepted, указывающим, что запрос был принят для обработки.
     */
    @PostMapping("/email-confirmation/resend")
    public ResponseEntity<Void> resendConfirmationEmail(@RequestBody @Valid ResendVerificationRequest request) {
        authenticationService.resendVerificationEmail(request);

        return ResponseEntity.accepted().build();
    }

    /**
     * Запрос на восстановление пароля
     *
     * @param request данные для восстановления пароля (email)
     * @return сообщение о статусе операции
     */
    @PostMapping("/password-reset/request")
    public ResponseEntity<Void> forgotPassword(@RequestBody @Valid ForgotPasswordRequest request) {
        authenticationService.forgotPassword(request);
        return ResponseEntity.accepted().build();
    }

    /**
     * Сброс пароля пользователя по токену
     *
     * @param request новый пароль
     * @return сообщение о статусе операции
     */
    @PostMapping("/password-reset")
    public ResponseEntity<Void> resetPassword(@RequestBody @Valid ResetPasswordRequest request) {
        authenticationService.resetPassword(request);
        //TODO:Придумать как отозвать все рефреш токены
        return ResponseEntity.ok().build();
    }

    /**
     * Обновление токена доступа
     *
     * @param refreshToken токен обновления из cookie
     * @param response HTTP-ответ для установки обновленного cookie
     * @return новый токен доступа
     */
    @PostMapping("/refresh")
    public ResponseEntity<AuthenticationResponse> refreshToken(@CookieValue(name = "refresh_token") @NotNull String refreshToken,
                                                               HttpServletResponse response) {
        Tokens tokens = authenticationService.refreshToken(refreshToken);
        ResponseCookie cookie = createRefreshTokenCookie(tokens.getRefreshToken(), Duration.ofDays(7));
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());

        return ResponseEntity.ok(new AuthenticationResponse(tokens.getToken()));
    }

    /**
     * Выход пользователя из системы
     *
     * @param refreshToken токен обновления из cookie
     * @param response HTTP-ответ для очистки cookie
     * @return статус операции
     */
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@CookieValue(name = "refresh_token") String refreshToken,
                                       HttpServletResponse response) {
        refreshTokenService.revokeRefreshToken(refreshToken);
        ResponseCookie cookie = createRefreshTokenCookie("", Duration.ZERO);
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());

        return ResponseEntity.noContent().build();
    }

    /**
     * Выход пользователя из системы со всех устройств
     *
     * @param refreshToken токен обновления из cookie
     * @param response HTTP-ответ для очистки cookie
     * @return статус операции
     */
    @PostMapping("/logout/all")
    public ResponseEntity<Void> revokeAllRefreshTokens(@CookieValue(name = "refresh_token") String refreshToken,
        HttpServletResponse response){
        refreshTokenService.revokeAllUserTokens(refreshToken);
        ResponseCookie cookie = createRefreshTokenCookie("", Duration.ZERO);
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
        return ResponseEntity.noContent().build();
    }

}
