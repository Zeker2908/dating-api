package ru.zeker.authenticationservice.domain.mapper;

import org.mapstruct.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import ru.zeker.authenticationservice.domain.dto.OAuth2UserInfo;
import ru.zeker.authenticationservice.domain.dto.request.RegisterRequest;
import ru.zeker.authenticationservice.domain.dto.response.UserResponse;
import ru.zeker.authenticationservice.domain.model.entity.LocalAuth;
import ru.zeker.authenticationservice.domain.model.entity.OAuthAuth;
import ru.zeker.authenticationservice.domain.model.entity.User;
import ru.zeker.authenticationservice.domain.model.enums.OAuth2Provider;

import static ru.zeker.authenticationservice.domain.model.enums.Role.ADMIN;

@Mapper(componentModel = "spring")
public interface UserMapper {


    // Email нормализуется к lower case в сервисных методах
    @Mapping(target = "role", constant = "USER")
    User toEntity(RegisterRequest request, @Context PasswordEncoder passwordEncoder);

    @Mapping(target = "role", constant = "ADMIN")
    User toAdmin(RegisterRequest request, @Context PasswordEncoder passwordEncoder);

    @Mapping(target = "role", constant = "USER")
    User toOAuthEntity(OAuth2UserInfo userInfo, OAuth2Provider provider);

    @Mapping(target = "isLocalUser", expression = "java(user.getLocalAuth() != null)")
    @Mapping(target = "isOAuthUser", expression = "java(user.getOauthAuth() != null)")
    UserResponse toResponse(User user);

    @AfterMapping
    default void setLocalAuth(@MappingTarget User user, RegisterRequest request,
                              @Context PasswordEncoder passwordEncoder) {
        boolean isAdmin = ADMIN.equals(user.getRole());
        user.setLocalAuth(LocalAuth.builder()
                .user(user)
                .password(passwordEncoder.encode(request.getPassword()))
                .enabled(isAdmin)
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
