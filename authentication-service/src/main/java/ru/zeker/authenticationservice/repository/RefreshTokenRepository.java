package ru.zeker.authenticationservice.repository;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;
import ru.zeker.authenticationservice.domain.model.entity.RefreshToken;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;

@Repository
public interface RefreshTokenRepository extends CrudRepository<RefreshToken, String> {
    Optional<RefreshToken> findByToken(String token);
    Optional<Set<RefreshToken>> findAllByUserId(UUID id);
}
