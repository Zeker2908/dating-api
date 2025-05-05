package ru.zeker.authenticationservice.service;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import ru.zeker.authenticationservice.domain.dto.Tokens;
import ru.zeker.authenticationservice.domain.dto.request.*;
import ru.zeker.authenticationservice.domain.mapper.UserMapper;
import ru.zeker.authenticationservice.domain.model.entity.LocalAuth;
import ru.zeker.authenticationservice.domain.model.entity.RefreshToken;
import ru.zeker.authenticationservice.domain.model.entity.User;
import ru.zeker.authenticationservice.exception.InvalidTokenException;
import ru.zeker.authenticationservice.exception.TooManyRequestsException;
import ru.zeker.authenticationservice.exception.UserAlreadyEnableException;
import ru.zeker.common.dto.kafka.EmailEvent;
import ru.zeker.common.dto.kafka.EmailEventType;
import ru.zeker.common.util.JwtUtils;

import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Сервис для управления аутентификацией и регистрацией пользователей
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserService userService;
    private final UserMapper userMapper;
    private final JwtService jwtService;
    private final JwtUtils jwtUtils;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final RefreshTokenService refreshTokenService;
    private final KafkaProducer kafkaProducer;
    private final PasswordHistoryService passwordHistoryService;
    private final VerificationCooldownService verificationCooldownService;

    /**
     * Регистрация нового пользователя и отправка сообщения для верификации email
     *
     * @param request данные нового пользователя
     */
    @Transactional
    public void register(RegisterRequest request) {
        String email = request.getEmail().toLowerCase();
        log.info("Регистрация нового пользователя с email: {}", email);

        User user = userMapper.toEntity(request, passwordEncoder);

        userService.create(user);
        log.debug("Пользователь создан в базе данных: {}", email);

        passwordHistoryService.create(user, request.getPassword());
        log.debug("История паролей создана в базе данных");

        String token = jwtService.generateEmailToken(user);
        EmailEvent userRegisteredEvent = createEmailEvent(user,
                EmailEventType.EMAIL_VERIFICATION,
                Map.of("token", token));

        kafkaProducer.sendEmailEvent(userRegisteredEvent);
        log.info("Отправлено сообщение для верификации email: {}", email);
    }

    /**
     * Аутентификация пользователя и выдача токенов
     *
     * @param request данные для входа
     * @return объект с JWT и refresh токенами
     */
    public Tokens login(LoginRequest request) {
        String email = request.getEmail().toLowerCase();
        log.info("Попытка входа пользователя: {}", email);

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        email,
                        request.getPassword()
                )
        );

        User user = (User) authentication.getPrincipal();

        log.debug("Аутентификация успешна для пользователя: {}", email);
        
        String jwtToken = jwtService.generateAccessToken(user);
        String refreshToken = refreshTokenService.createRefreshToken(user);
        
        log.info("Пользователь успешно вошел в систему: {}", email);
        
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
        
        String jwtToken = jwtService.generateAccessToken(user);
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
     * @param request запрос с JWT токен для подтверждения
     * @throws InvalidTokenException если токен недействителен
     * @throws UserAlreadyEnableException если email уже подтвержден
     */
    public void confirmEmail(ConfirmationEmailRequest request) {
        log.info("Запрос на подтверждение email");
        String token = request.getToken();
        
        User user = userService.findById(jwtService.extractUserId(token));
        
        if (!jwtService.isTokenValid(token, user)) {
            log.warn("Попытка подтверждения email с недействительным токеном");
            throw new InvalidTokenException();
        }
        
        if (user.isEnabled()) {
            log.warn("Попытка повторного подтверждения уже активированной учетной записи: {}", user.getEmail());
            throw new UserAlreadyEnableException();
        }
        
        user.getLocalAuth().setEnabled(true);
        userService.update(user);
        
        log.info("Email успешно подтвержден для пользователя: {}", user.getEmail());
    }

    /**
     * Обработка запроса на восстановление пароля.
     * Отправляет email с инструкциями для сброса пароля
     *
     * @param request запрос с email пользователя
     */
    public void forgotPassword(UserUpdateRequest request) {
        String email = request.getEmail().toLowerCase();
        log.info("Запрос на восстановление пароля для: {}", email);
        
        User user = userService.findByEmail(email);
        String token = jwtService.generateEmailToken(user);
        
        EmailEvent event = createEmailEvent(user,
                EmailEventType.FORGOT_PASSWORD,
                Map.of("token", token));

        kafkaProducer.sendEmailEvent(event);
        log.info("Письмо с инструкцией для восстановления пароля отправлено на email: {}", email);
    }

    /**
     * Сброс пароля пользователя по токену
     *
     * @param request запрос с новым паролем
     * @throws InvalidTokenException если токен недействителен
     */
    @Transactional
    public void resetPassword(ResetPasswordRequest request) {
        log.info("Запрос на сброс пароля");
        String token = request.getToken();
        String password = request.getPassword();
        String encodedPassword = passwordEncoder.encode(password);

        // Объединенные проверки токена
        if (jwtUtils.isTokenExpired(token) || 
            !userService.findById(jwtService.extractUserId(token)).getVersion().equals(jwtService.extractVersion(token)) ||
            !jwtUtils.isValidUsername(token, userService.findById(jwtService.extractUserId(token)).getEmail())) {
            log.warn("Недействительный токен для сброса пароля");
            throw new InvalidTokenException();
        }

        User user = userService.findById(jwtService.extractUserId(token));

        LocalAuth localAuth = Optional.ofNullable(user.getLocalAuth())
                .orElseGet(()->{
                    LocalAuth localAuthNew = LocalAuth.builder()
                            .user(user)
                            .enabled(true)
                            .build();
                    user.setLocalAuth(localAuthNew);
                    return localAuthNew;
                });
        localAuth.setPassword(encodedPassword);

        passwordHistoryService.create(user, password);
        userService.update(user);
        refreshTokenService.revokeAllUserTokens(token);

        log.info("Пароль успешно сброшен для пользователя: {}", user.getEmail());
    }

    /**
     * Повторно отправляет письмо с подтверждением указанному пользователю, если он еще не проверен
     * и если период восстановления истек.
     * Запрос @param содержит адрес электронной почты для повторной отправки подтверждения
     * @throws UserAlreadyEnableException, если пользователь уже проверен
     * @throws TooManyRequestsException, если письмо было запрошено слишком недавно
     */
    public void resendVerificationEmail(ResendVerificationRequest request) {
        log.info("Запрос на повторную отправку письма с подтверждением");
        String email = request.getEmail().toLowerCase();
        User user = userService.findByEmail(email);

        if (user.isEnabled()){
            log.warn("Пользователь уже подтвержден: {}", email);
            throw new UserAlreadyEnableException();
        }

        if(!verificationCooldownService.canResendEmail(email)) {
            log.warn("Попытка повторного отправить письмо с подтверждением слишком часто: {}", email);
            throw new TooManyRequestsException();
        }

        String token = jwtService.generateEmailToken(user);
        EmailEvent event = createEmailEvent(user,
                EmailEventType.EMAIL_VERIFICATION,
                Map.of("token", token));

        kafkaProducer.sendEmailEvent(event);
        verificationCooldownService.updateCooldown(email);
        log.info("Письмо с подтверждением отправлено на email: {}", email);

    }

    private EmailEvent createEmailEvent(User user, EmailEventType type, Map<String, String> data) {
        return EmailEvent.builder()
                .type(type)
                .id(UUID.randomUUID().toString())
                .email(user.getEmail())
                .payload(data)
                .build();
    }
}
