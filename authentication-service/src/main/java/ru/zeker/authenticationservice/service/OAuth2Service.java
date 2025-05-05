package ru.zeker.authenticationservice.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.zeker.authenticationservice.domain.dto.OAuth2UserInfo;
import ru.zeker.authenticationservice.domain.mapper.UserMapper;
import ru.zeker.authenticationservice.domain.model.entity.User;
import ru.zeker.authenticationservice.domain.model.enums.OAuth2Provider;
import ru.zeker.authenticationservice.exception.OAuth2ProviderException;
import ru.zeker.authenticationservice.repository.UserRepository;

/**
 * Сервис для обработки OAuth2-аутентификации пользователей.
 * Отвечает за регистрацию новых пользователей или обновление существующих при входе через сторонних провайдеров.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class OAuth2Service {

    private final UserRepository userRepository;
    private final UserMapper userMapper;

    /**
     * Обрабатывает вход OAuth2-пользователя. Выполняет:
     * <ul>
     *     <li>Проверку email и его подтверждение</li>
     *     <li>Извлечение информации о пользователе</li>
     *     <li>Регистрацию нового пользователя или обновление существующего</li>
     * </ul>
     *
     * @param oAuth2User   Пользователь, полученный от OAuth2-провайдера
     * @param providerName Название провайдера (например, "google", "github")
     * @return Зарегистрированный или обновлённый пользователь
     * @throws OAuth2ProviderException если email не верифицирован
     * @throws IllegalArgumentException если провайдер неизвестен
     */
    @Transactional
    public User processOauth2User(OAuth2User oAuth2User, String providerName) {
        Boolean emailVerified = oAuth2User.getAttribute("email_verified");
        String email = oAuth2User.getAttribute("email");
        log.info("Обработка пользователя OAuth2: email={}, emailVerified={}", email, emailVerified);

        if (emailVerified == null || !emailVerified) {
            log.warn("Ошибка аутентификации OAuth2: адрес электронной почты не проверен для email={}", email);
            throw new OAuth2ProviderException("Email не верифицирован");
        }

        OAuth2Provider oAuth2Provider = extractProvider(providerName);
        OAuth2UserInfo userInfo = oAuth2Provider.extractUserInfo(oAuth2User.getAttributes());

        return userRepository.findByEmail(email)
                .map(u -> update(u, userInfo, oAuth2Provider))
                .orElseGet(() -> register(userInfo, oAuth2Provider));
    }

    /**
     * Обновляет существующего пользователя, добавляя информацию об OAuth2-провайдере,
     * если она ранее не была сохранена.
     *
     * @param user            Существующий пользователь
     * @param userInfo        Информация, полученная от OAuth2-провайдера
     * @param oAuth2Provider  Провайдер OAuth2
     * @return Обновлённый пользователь
     */
    private User update(User user, OAuth2UserInfo userInfo, OAuth2Provider oAuth2Provider) {
        if (user.getOauthAuth() == null) {
            userMapper.setOAuthAuth(user, userInfo, oAuth2Provider);
            log.info("Пользователю успешно добавлена OAuth2 аутентификация");
            return userRepository.save(user);
        }
        return user;
    }

    /**
     * Регистрирует нового пользователя на основе информации, полученной от OAuth2-провайдера.
     *
     * @param userInfo       Информация о пользователе
     * @param oAuth2Provider Провайдер OAuth2
     * @return Новый пользователь
     */
    private User register(OAuth2UserInfo userInfo, OAuth2Provider oAuth2Provider) {
        User user = userMapper.toOAuthEntity(userInfo, oAuth2Provider);
        log.debug("Создан новый объект пользователя для регистрации OAuth2");

        userRepository.save(user);
        log.info("Успешно зарегистрированный пользователь OAuth2: id={}, email={}", user.getId(), user.getEmail());
        return user;
    }

    /**
     * Преобразует строковое имя провайдера в соответствующее перечисление {@link OAuth2Provider}.
     *
     * @param provider Название провайдера (например, "google")
     * @return Значение перечисления {@link OAuth2Provider}
     * @throws IllegalArgumentException если провайдер неизвестен
     */
    private OAuth2Provider extractProvider(String provider) {
        try {
            return OAuth2Provider.valueOf(provider.toUpperCase());
        } catch (Exception e) {
            log.error("Не удалось получить OAuth2Provider");
            throw new IllegalArgumentException("Не удалось получить OAuth2Provider");
        }
    }
}