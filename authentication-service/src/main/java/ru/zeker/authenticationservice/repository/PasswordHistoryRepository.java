package ru.zeker.authenticationservice.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import ru.zeker.authenticationservice.domain.model.entity.PasswordHistory;

import java.util.Set;
import java.util.UUID;


@Repository
public interface PasswordHistoryRepository extends JpaRepository<PasswordHistory, UUID> {
    Set<PasswordHistory> findAllByLocalAuthId(UUID userId);
    Boolean existsByLocalAuthIdAndPassword(UUID userId, String password);
}
