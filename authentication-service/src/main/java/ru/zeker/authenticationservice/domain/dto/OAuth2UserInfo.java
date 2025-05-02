package ru.zeker.authenticationservice.domain.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class OAuth2UserInfo {
    private String email;
    private String oAuthId;
}
