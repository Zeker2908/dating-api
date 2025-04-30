package ru.zeker.authenticationservice.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import ru.zeker.authenticationservice.domain.dto.request.*;
import ru.zeker.authenticationservice.domain.mapper.UserMapper;
import ru.zeker.common.component.JwtUtils;
import ru.zeker.common.dto.kafka.EmailEvent;
import ru.zeker.authenticationservice.domain.dto.*;
import ru.zeker.authenticationservice.domain.model.entity.RefreshToken;
import ru.zeker.authenticationservice.domain.model.entity.User;
import ru.zeker.authenticationservice.exception.InvalidTokenException;
import ru.zeker.authenticationservice.exception.UserAlreadyEnableException;
import ru.zeker.common.dto.kafka.EmailEventType;

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

    /**
     * Регистрация нового пользователя и отправка сообщения для верификации email
     *
     * @param request данные нового пользователя
     */
    public void register(RegisterRequest request) {
        log.info("Регистрация нового пользователя с email: {}", request.getEmail());

        User user = userMapper.toEntity(request);
                
        userService.create(user);
        log.debug("Пользователь создан в базе данных: {}", user.getEmail());
        
        String token = jwtService.generateAccessToken(user);
        EmailEvent userRegisteredEvent = EmailEvent.builder()
                .type(EmailEventType.EMAIL_VERIFICATION)
                .id(UUID.randomUUID().toString())
                .email(user.getEmail())
                .token(token)
                .firstName(user.getFirstName())
                .build();
                
        kafkaProducer.sendEmailEvent(userRegisteredEvent);
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
        
        String jwtToken = jwtService.generateAccessToken(user);
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
        
        user.setEnabled(true);
        userService.update(user);
        
        log.info("Email успешно подтвержден для пользователя: {}", user.getEmail());
    }

    /**
     * Обработка запроса на восстановление пароля.
     * Отправляет email с инструкциями для сброса пароля
     *
     * @param request запрос с email пользователя
     */
    public void forgotPassword(ForgotPasswordRequest request) {
        log.info("Запрос на восстановление пароля для: {}", request.getEmail());
        
        User user = userService.findByEmail(request.getEmail());
        String token = jwtService.generateOnceVerificationToken(user);
        
        EmailEvent event = EmailEvent.builder()
                .type(EmailEventType.FORGOT_PASSWORD)
                .id(UUID.randomUUID().toString())
                .email(user.getEmail())
                .token(token)
                .firstName(user.getFirstName())
                .build();

        kafkaProducer.sendEmailEvent(event);
        log.info("Письмо с инструкцией для восстановления пароля отправлено на email: {}", user.getEmail());
    }

    /**
     * Сброс пароля пользователя по токену
     *
     * @param request запрос с новым паролем
     * @throws InvalidTokenException если токен недействителен
     */
    public void resetPassword(ResetPasswordRequest request) {
        log.info("Запрос на сброс пароля");
        String token = request.getToken();
        String password = request.getPassword();

        if(jwtUtils.isTokenExpired(token)) {
            log.warn("Попытка сброса пароля с просроченным токеном");
            throw new InvalidTokenException();
        }

        User user = userService.findById(jwtService.extractUserId(token));

        if(!user.getVersion().equals(jwtService.extractVersion(token))){
            log.warn("Попытка сбросить пароль с измененными пользовательскими данными ");
            throw new InvalidTokenException();
        }

        if (!jwtUtils.isValidUsername(token, user.getEmail())) {
            log.warn("Попытка сброса пароля с недействительными данными токена");
            throw new InvalidTokenException();
        }

        passwordHistoryService.savePassword(user, password);

        user.setPassword(passwordEncoder.encode(password));
        userService.update(user);

        refreshTokenService.revokeAllUserTokens(token);

        log.info("Пароль успешно сброшен для пользователя: {}", user.getEmail());

    }
}
