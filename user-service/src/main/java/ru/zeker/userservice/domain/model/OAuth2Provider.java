package ru.zeker.userservice.domain.model;

import ru.zeker.userservice.domain.dto.OAuth2UserInfo;

import java.util.Map;

public enum OAuth2Provider {
    GOOGLE{
        @Override
        public OAuth2UserInfo extractUserInfo(Map<String, Object> attributes) {
            return new OAuth2UserInfo(
                    (String) attributes.get("email"),
                    (String) attributes.get("given_name"),
                    (String) attributes.get("family_name"),
                    (String) attributes.get("sub")
            );

        }
    };


    public abstract OAuth2UserInfo extractUserInfo(Map<String, Object> attributes);
}
