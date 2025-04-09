package ru.zeker.user_service.repository;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;
import ru.zeker.user_service.domain.model.RefreshToken;

import java.util.List;
import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends CrudRepository<RefreshToken, String> {
    Optional<RefreshToken> findByToken(String token);
    List<RefreshToken> findAllByUserId(Long id);
}
