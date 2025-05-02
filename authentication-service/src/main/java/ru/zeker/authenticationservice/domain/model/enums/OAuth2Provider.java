package ru.zeker.authenticationservice.domain.model.enums;

import ru.zeker.authenticationservice.domain.dto.OAuth2UserInfo;

import java.util.Map;

public enum OAuth2Provider {
    GOOGLE{

        @Override
        public OAuth2UserInfo extractUserInfo(Map<String, Object> attributes) {
            return new OAuth2UserInfo(
                    (String) attributes.get("email"),
                    (String) attributes.get("sub")
            );

        }
    };



    /**
     * Извлекает информацию о пользователе из заданных атрибутов OAuth2.
     *
     * @param attributes атрибутов от поставщика OAuth2
     * @return извлеченная информация о пользователе
     */
    public abstract OAuth2UserInfo extractUserInfo(Map<String, Object> attributes);
}
