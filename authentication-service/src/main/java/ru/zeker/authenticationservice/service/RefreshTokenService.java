package ru.zeker.authenticationservice.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import ru.zeker.authenticationservice.domain.model.entity.RefreshToken;
import ru.zeker.authenticationservice.domain.model.entity.User;
import ru.zeker.authenticationservice.exception.TokenExpiredException;
import ru.zeker.authenticationservice.exception.TokenNotFoundException;
import ru.zeker.authenticationservice.exception.UserNotFoundException;
import ru.zeker.authenticationservice.repository.RefreshTokenRepository;
import ru.zeker.common.config.JwtProperties;

import java.util.Date;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * Реализация сервиса для управления refresh-токенами
 * Обеспечивает создание, проверку, обновление и отзыв refresh-токенов
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class RefreshTokenService {
    private final JwtService jwtService;
    private final JwtProperties jwtProperties;
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserService userService;

    /**
     * Создает новый refresh-токен для пользователя
     *
     * @param user пользователь, для которого создается токен
     * @return строка refresh-токена
     */
    public String createRefreshToken(User user) {
        log.debug("Создание нового refresh-токена для пользователя с ID: {}", user.getId());
        
        String token = jwtService.generateRefreshToken(user);
        Date expiryDate = new Date(System.currentTimeMillis() + jwtProperties.getRefresh().getExpiration());
        long ttlSeconds = TimeUnit.MILLISECONDS.toSeconds(expiryDate.getTime() - System.currentTimeMillis());

        RefreshToken refreshToken = RefreshToken.builder()
                .token(token)
                .userId(user.getId())
                .expiryDate(expiryDate)
                .ttl(ttlSeconds)
                .build();

        RefreshToken savedToken = refreshTokenRepository.save(refreshToken);
        log.debug("Refresh-токен успешно сохранен в базе данных, срок действия: {} секунд", ttlSeconds);
        
        return savedToken.getToken();
    }

    /**
     * Проверяет действительность refresh-токена
     *
     * @param token строка refresh-токена для проверки
     * @return объект RefreshToken, если токен действителен
     * @throws TokenExpiredException если токен истек или отозван
     * @throws TokenNotFoundException если токен не найден
     */
    public RefreshToken verifyRefreshToken(String token) {
        log.debug("Проверка refresh-токена");

        return refreshTokenRepository.findByToken(token)
                .map(t -> {
                    if (t.getExpiryDate().before(new Date())) {
                        log.warn("Попытка использовать истекший токен для пользователя с ID: {}", t.getUserId());
                        refreshTokenRepository.delete(t);
                        throw new TokenExpiredException("Срок действия токена истек");
                    }

                    log.debug("Refresh-токен действителен для пользователя с ID: {}", t.getUserId());
                    return t;
                })
                .orElseThrow(() -> {
                    log.warn("Токен не найден в базе данных");
                    return new TokenNotFoundException("Refresh-токен не найден");
                });
    }

    /**
     * Обновляет refresh-токен, удаляя старый и создавая новый
     *
     * @param token объект старого refresh-токена
     * @return строка нового refresh-токена
     */
    public String rotateRefreshToken(RefreshToken token) {
        log.debug("Обновление refresh-токена для пользователя с ID: {}", token.getUserId());
        
        refreshTokenRepository.delete(token);
        log.debug("Старый refresh-токен удален");
        
        User user = userService.findById(token.getUserId());
        String newToken = createRefreshToken(user);
        
        log.info("Refresh-токен успешно обновлен для пользователя с ID: {}", token.getUserId());
        return newToken;
    }

    /**
     * Отзывает refresh-токен, делая его недействительным
     *
     * @param token строка refresh-токена для отзыва
     */
    public void revokeRefreshToken(String token) {
        log.debug("Запрос на отзыв refresh-токена");
        
        refreshTokenRepository.findByToken(token)
                .ifPresent(t -> {
                    log.info("Отзыв refresh-токена для пользователя с ID: {}", t.getUserId());
                    refreshTokenRepository.delete(t);
                });
    }

    /**
     * Отзывает все refresh-токены пользователя
     *
     * @param token токен пользователя
     */
    public void revokeAllUserTokens(String token) {
        UUID userId = jwtService.extractUserId(token);
        log.info("Отзыв всех refresh-токенов для пользователя с ID: {}", userId);
        
        Set<RefreshToken> tokens = refreshTokenRepository.findAllByUserId(userId).orElseThrow(() -> {
            log.warn("Пользователь с ID: {} не имеет refresh-токенов", userId);
            return new UserNotFoundException("Пользователь с ID: " + userId + " не имеет refresh-токенов");
        });

        refreshTokenRepository.deleteAll(tokens);
        
        log.info("Отозвано {} токенов для пользователя с ID: {}", tokens.size(), userId);
    }


}
