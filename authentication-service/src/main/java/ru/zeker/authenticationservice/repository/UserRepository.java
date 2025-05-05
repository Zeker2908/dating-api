package ru.zeker.authenticationservice.repository;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import ru.zeker.authenticationservice.domain.model.entity.User;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserRepository extends JpaRepository<User, UUID> {
    @EntityGraph(attributePaths = {"localAuth", "oauthAuth"})
    Optional<User> findByEmail(String email);

    Boolean existsByEmail(String email);
}
