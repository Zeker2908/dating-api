package ru.zeker.authenticationservice.domain.mapper;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import ru.zeker.authenticationservice.domain.dto.request.RegisterRequest;
import ru.zeker.authenticationservice.domain.dto.response.UserResponse;
import ru.zeker.authenticationservice.domain.model.entity.User;

@Mapper(componentModel = "spring",
        imports = {org.springframework.util.StringUtils.class,
                ru.zeker.authenticationservice.domain.model.enums.Role.class})
public interface UserMapper {

    @Mapping(target = "email", expression = "java(request.getEmail().toLowerCase())")
    @Mapping(target = "firstName", expression = "java(StringUtils.capitalize(request.getFirstName().trim()))")
    @Mapping(target = "lastName", expression = "java(StringUtils.capitalize(request.getLastName().trim()))")
    @Mapping(target = "role", expression = "java(Role.USER)")
    @Mapping(target = "enabled", constant = "false")
    @Mapping(target = "locked", constant = "false")
    User toEntity(RegisterRequest request);

    UserResponse toResponse(User user);
}
