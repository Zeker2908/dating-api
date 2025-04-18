package ru.zeker.userservice.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import ru.zeker.userservice.domain.dto.OAuth2UserInfo;
import ru.zeker.userservice.domain.model.OAuth2Provider;
import ru.zeker.userservice.domain.model.Role;
import ru.zeker.userservice.domain.model.User;

import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class OAuth2Service {
    private final UserService userService;
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
        String email = userInfo.getEmail();
        String firstName = userInfo.getFirstName();
        String lastName = userInfo.getLastName();
        String oAuthId = userInfo.getOAuthId();
        
        log.debug("Атрибуты регистрации OAuth2: email={}, firstName={}, lastName={}, oAuthId={}, availableAttrs={}",
                email, firstName, lastName, oAuthId, attributes.keySet());
        
        User user = User.builder()
                .email(email)
                .firstName(firstName)
                .lastName(lastName)
                .role(Role.USER)
                .provider(oAuth2Provider)
                .oAuthId(oAuthId)
                .enabled(true)
                .build();
        
        log.debug("Создан новый объект пользователя для регистрации OAuth2: {}", user);
        
        try {
            User createdUser = userService.create(user);
            log.info("Успешно зарегистрированный пользователь OAuth2: id={}, email={}", createdUser.getId(), createdUser.getEmail());
            return createdUser;
        } catch (Exception e) {
            log.error("Не удалось зарегистрировать пользователя OAuth2 с адресом электронной почты.={}: {}", email, e.getMessage(), e);
            throw e;
        }
    }
}
