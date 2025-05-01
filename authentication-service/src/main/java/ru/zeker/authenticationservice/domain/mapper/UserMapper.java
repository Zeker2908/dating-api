package ru.zeker.authenticationservice.domain.mapper;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import ru.zeker.authenticationservice.domain.dto.OAuth2UserInfo;
import ru.zeker.authenticationservice.domain.dto.request.RegisterRequest;
import ru.zeker.authenticationservice.domain.dto.response.UserResponse;
import ru.zeker.authenticationservice.domain.model.entity.User;
import ru.zeker.authenticationservice.domain.model.enums.OAuth2Provider;

@Mapper(componentModel = "spring",
        imports = {org.springframework.util.StringUtils.class,
                ru.zeker.authenticationservice.domain.model.enums.Role.class})
public interface UserMapper {

    // Email нормализуется к lower case в сервисных методах
    @Mapping(target = "email", expression = "java(request.getEmail())")
    @Mapping(target = "firstName", expression = "java(StringUtils.capitalize(request.getFirstName().trim()))")
    @Mapping(target = "lastName", expression = "java(StringUtils.capitalize(request.getLastName().trim()))")
    @Mapping(target = "role", constant = "USER")
    @Mapping(target = "enabled", constant = "false")
    @Mapping(target = "locked", constant = "false")
    User toEntity(RegisterRequest request);

    @Mapping(target = "email",      expression = "java(userInfo.getEmail())")
    @Mapping(target = "firstName",  expression = "java(StringUtils.capitalize(userInfo.getFirstName()))")
    @Mapping(target = "lastName",   expression = "java(StringUtils.capitalize(userInfo.getLastName()))")
    @Mapping(target = "oAuthId",    expression = "java(userInfo.getOAuthId())")
    @Mapping(target = "provider",   expression = "java(provider)")
    @Mapping(target = "role",       constant = "USER")
    @Mapping(target = "enabled",    constant = "true")
    @Mapping(target = "locked",     constant = "false")
    User toOAuthEntity(OAuth2UserInfo userInfo, OAuth2Provider provider);

    UserResponse toResponse(User user);
}
