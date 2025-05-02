package ru.zeker.authenticationservice.domain.model.entity;

import jakarta.persistence.*;
import lombok.*;

import java.util.List;
import java.util.UUID;

@Getter
@Setter
@ToString
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
public class LocalAuth {

    @Id
    private UUID id;

    @OneToOne
    @MapsId
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    @Builder.Default
    private Boolean enabled = false;

    @OneToMany(mappedBy = "localAuth", cascade = CascadeType.REMOVE)
    @ToString.Exclude
    private List<PasswordHistory> passwordHistory;
}
