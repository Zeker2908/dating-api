package ru.zeker.authenticationservice.domain.model.entity;

import jakarta.persistence.*;
import lombok.*;
import ru.zeker.authenticationservice.domain.model.enums.OAuth2Provider;

import java.util.UUID;

@Getter
@Setter
@ToString
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
public class OAuthAuth {
    @Id
    private UUID id;

    @OneToOne
    @MapsId
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private OAuth2Provider provider;

    @Column(nullable = false)
    private String oAuthId;
}
