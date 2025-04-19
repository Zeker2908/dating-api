package ru.zeker.userservice.domain.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class OAuth2UserInfo {
    private String email;
    private String firstName;
    private String lastName;
    private String oAuthId;
}
