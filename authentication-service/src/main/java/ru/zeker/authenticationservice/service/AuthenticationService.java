package ru.zeker.authenticationservice.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import ru.zeker.authenticationservice.domain.dto.request.ForgotPasswordRequest;
import ru.zeker.authenticationservice.domain.dto.request.LoginRequest;
import ru.zeker.authenticationservice.domain.dto.request.RegisterRequest;
import ru.zeker.authenticationservice.domain.dto.request.ResetPasswordRequest;
import ru.zeker.common.dto.EmailEvent;
import ru.zeker.authenticationservice.domain.dto.*;
import ru.zeker.authenticationservice.domain.model.entity.RefreshToken;
import ru.zeker.authenticationservice.domain.model.enums.Role;
import ru.zeker.authenticationservice.domain.model.entity.User;
import ru.zeker.authenticationservice.exception.InvalidTokenException;
import ru.zeker.authenticationservice.exception.UserAlreadyEnableException;

import java.util.UUID;

/**
 * Сервис для управления аутентификацией и регистрацией пользователей
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserService userService;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final RefreshTokenService refreshTokenService;
    private final KafkaProducer kafkaProducer;
    private final PasswordHistoryService passwordHistoryService;

    /**
     * Регистрация нового пользователя и отправка сообщения для верификации email
     *
     * @param request данные нового пользователя
     */
    public void register(RegisterRequest request) {
        log.info("Регистрация нового пользователя с email: {}", request.getEmail());
        
        User user = User.builder()
                .email(request.getEmail().toLowerCase())
                .password(request.getPassword())
                .firstName(StringUtils.capitalize(request.getFirstName().trim()))
                .lastName(StringUtils.capitalize(request.getLastName().trim()))
                .role(Role.USER)
                .enabled(false)
                .locked(false)
                .build();
                
        userService.create(user);
        log.debug("Пользователь создан в базе данных: {}", user.getEmail());
        
        String token = jwtService.generateToken(user);
        EmailEvent userRegisteredEvent = EmailEvent.builder()
                .id(UUID.randomUUID().toString())
                .email(user.getEmail())
                .token(token)
                .firstName(user.getFirstName())
                .build();
                
        kafkaProducer.sendEmailVerification(userRegisteredEvent);
        log.info("Отправлено сообщение для верификации email: {}", user.getEmail());
    }

    /**
     * Аутентификация пользователя и выдача токенов
     *
     * @param request данные для входа
     * @return объект с JWT и refresh токенами
     */
    public Tokens login(LoginRequest request) {
        log.info("Попытка входа пользователя: {}", request.getEmail());
        
        User user = userService.findByEmail(request.getEmail());

        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getEmail().toLowerCase(),
                            request.getPassword()
                    )
            );
        }catch (BadCredentialsException ex){
            throw new BadCredentialsException("Неверный логин или пароль");
        }
        
        log.debug("Аутентификация успешна для пользователя: {}", user.getEmail());
        
        String jwtToken = jwtService.generateToken(user);
        String refreshToken = refreshTokenService.createRefreshToken(user);
        
        log.info("Пользователь успешно вошел в систему: {}", user.getEmail());
        
        return Tokens.builder()
                .token(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }

    /**
     * Обновление JWT токена по refresh токену
     *
     * @param refreshToken токен обновления
     * @return новый набор токенов
     */
    public Tokens refreshToken(String refreshToken) {
        log.debug("Запрос на обновление токена");
        
        RefreshToken token = refreshTokenService.verifyRefreshToken(refreshToken);
        User user = userService.findById(token.getUserId());
        
        String jwtToken = jwtService.generateToken(user);
        String newRefreshToken = refreshTokenService.rotateRefreshToken(token);
        
        log.debug("Токены успешно обновлены для пользователя: {}", user.getEmail());
        
        return Tokens.builder()
                .token(jwtToken)
                .refreshToken(newRefreshToken)
                .build();
    }

    /**
     * Подтверждение email пользователя
     *
     * @param token JWT токен для подтверждения
     * @throws InvalidTokenException если токен недействителен
     * @throws UserAlreadyEnableException если email уже подтвержден
     */
    public void confirmEmail(String token) {
        log.info("Запрос на подтверждение email");
        
        User user = userService.findById(jwtService.extractUserId(token));
        
        if (!jwtService.isTokenValid(token, user)) {
            log.warn("Попытка подтверждения email с недействительным токеном");
            throw new InvalidTokenException();
        }
        
        if (user.isEnabled()) {
            log.warn("Попытка повторного подтверждения уже активированной учетной записи: {}", user.getEmail());
            throw new UserAlreadyEnableException();
        }
        
        user.setEnabled(true);
        userService.update(user);
        
        log.info("Email успешно подтвержден для пользователя: {}", user.getEmail());
    }

    /**
     * Обработка запроса на восстановление пароля
     * Отправляет email с инструкциями для сброса пароля
     *
     * @param request запрос с email пользователя
     */
    public void forgotPassword(ForgotPasswordRequest request) {
        log.info("Запрос на восстановление пароля для: {}", request.getEmail());
        
        User user = userService.findByEmail(request.getEmail());
        String token = jwtService.generateToken(user);
        
        EmailEvent event = EmailEvent.builder()
                .id(UUID.randomUUID().toString())
                .email(user.getEmail())
                .token(token)
                .firstName(user.getFirstName())
                .build();

        kafkaProducer.sendForgotPassword(event);
        log.info("Письмо с инструкцией для восстановления пароля отправлено на email: {}", user.getEmail());
    }

    /**
     * Сброс пароля пользователя по токену
     *
     * @param request запрос с новым паролем
     * @param token JWT токен для подтверждения
     * @throws InvalidTokenException если токен недействителен
     */
    public void resetPassword(ResetPasswordRequest request, String token) {
        log.info("Запрос на сброс пароля");
        
        User user = userService.findById(jwtService.extractUserId(token));
        
        if (!jwtService.isTokenValid(token, user)) {
            log.warn("Попытка сброса пароля с недействительным токеном");
            throw new InvalidTokenException();
        }
        
        // Сохраняем новый пароль в истории паролей
        passwordHistoryService.savePassword(user, request.getPassword());
        
        // Устанавливаем новый пароль
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        userService.update(user);
        
        refreshTokenService.revokeAllUserTokens(token);
        
        log.info("Пароль успешно сброшен для пользователя: {}", user.getEmail());
    }
}
