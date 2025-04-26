package ru.zeker.authenticationservice.domain.model.entity;


import jakarta.persistence.*;
import lombok.*;
import ru.zeker.common.model.BaseEntity;

@EqualsAndHashCode(callSuper = true)
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(indexes = @Index(name = "idx_password_history_user", columnList = "user_id"))
public class PasswordHistory extends BaseEntity {

    @JoinColumn(name = "user_id", nullable = false)
    @ManyToOne
    private User user;

    @Column(nullable = false)
    private String password;
}
