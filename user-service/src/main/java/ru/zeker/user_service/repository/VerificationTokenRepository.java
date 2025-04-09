package ru.zeker.user_service.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import ru.zeker.user_service.domain.model.VerificationToken;

import java.util.Optional;

@Repository
public interface VerificationTokenRepository extends JpaRepository<VerificationToken, Long> {
    void deleteAllByUserId(Long userId);

    Optional<VerificationToken> findByToken(String token);
}
