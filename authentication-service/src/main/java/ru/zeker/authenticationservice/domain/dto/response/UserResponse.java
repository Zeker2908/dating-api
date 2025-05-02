package ru.zeker.authenticationservice.domain.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import ru.zeker.authenticationservice.domain.model.enums.Role;

import java.util.UUID;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class UserResponse {
    private UUID id;
    private String email;
    private Role role;
    boolean isLocalUser;
    boolean isOAuthUser;
}
