package ru.zeker.authenticationservice.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import ru.zeker.authenticationservice.domain.dto.OAuth2UserInfo;
import ru.zeker.authenticationservice.domain.mapper.UserMapper;
import ru.zeker.authenticationservice.domain.model.entity.User;
import ru.zeker.authenticationservice.domain.model.enums.OAuth2Provider;
import ru.zeker.authenticationservice.repository.UserRepository;

import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class OAuth2Service {
    private final UserService userService;
    private final UserMapper userMapper;
    /**
     * Регистрирует нового пользователя с помощью предоставленных строк OAuth2User и OAuth2Provider.
     *
     * @param oAuth2User OAuth2User для регистрации
     * @param provider строка OAuth2Provider
     * @return созданный пользователь
     */
    public User register(OAuth2User oAuth2User, String provider) {
        log.info("Запуск процесса регистрации пользователя OAuth2");

        OAuth2Provider oAuth2Provider;
        try {
            oAuth2Provider = OAuth2Provider.valueOf(provider.toUpperCase());
        } catch (Exception e) {
            log.error("Не удалось получить OAuth2Provider");
            throw new IllegalArgumentException("Не удалось получить OAuth2Provider");
        }

        Map<String, Object> attributes = oAuth2User.getAttributes();
        OAuth2UserInfo userInfo = oAuth2Provider.extractUserInfo(attributes);
        
        User user = userMapper.toOAuthEntity(userInfo, oAuth2Provider);
        
        log.debug("Создан новый объект пользователя для регистрации OAuth2");

        User createdUser = userService.create(user);
        log.info("Успешно зарегистрированный пользователь OAuth2: id={}, email={}", createdUser.getId(), createdUser.getEmail());
        return createdUser;

    }
}
