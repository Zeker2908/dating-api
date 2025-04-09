package ru.zeker.common.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class UserRegisteredEvent {
    private final String email;
    private final String token;
}
