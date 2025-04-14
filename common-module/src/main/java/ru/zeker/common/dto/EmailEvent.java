package ru.zeker.common.dto;

import lombok.*;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class EmailEvent {
    private String id;
    private String email;
    private String token;
    private String firstName;
}
