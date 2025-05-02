package ru.zeker.authenticationservice.domain.mapper;

import org.mapstruct.AfterMapping;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.MappingTarget;
import ru.zeker.authenticationservice.domain.dto.OAuth2UserInfo;
import ru.zeker.authenticationservice.domain.dto.request.RegisterRequest;
import ru.zeker.authenticationservice.domain.dto.response.UserResponse;
import ru.zeker.authenticationservice.domain.model.entity.LocalAuth;
import ru.zeker.authenticationservice.domain.model.entity.OAuthAuth;
import ru.zeker.authenticationservice.domain.model.entity.User;
import ru.zeker.authenticationservice.domain.model.enums.OAuth2Provider;

@Mapper(componentModel = "spring")
public interface UserMapper {

    // Email нормализуется к lower case в сервисных методах
    @Mapping(target = "role", constant = "USER")
    User toEntity(RegisterRequest request);

    @Mapping(target = "role", constant = "USER")
    User toOAuthEntity(OAuth2UserInfo userInfo, OAuth2Provider provider);

    @Mapping(target = "isLocalUser", expression = "java(user.getLocalAuth() != null)")
    @Mapping(target = "isOAuthUser", expression = "java(user.getOauthAuth() != null)")
    UserResponse toResponse(User user);

    @AfterMapping
    default void setLocalAuth(@MappingTarget User user, RegisterRequest request) {
        user.setLocalAuth(LocalAuth.builder()
                .user(user)
                .password(request.getPassword())
                .enabled(false)
                .build());
    }

    @AfterMapping
    default void setOAuthAuth(@MappingTarget User user,
                              OAuth2UserInfo userInfo,
                              OAuth2Provider provider) {
        user.setOauthAuth(OAuthAuth.builder()
                .user(user)
                .oAuthId(userInfo.getOAuthId())
                .provider(provider)
                .build());
    }
}
