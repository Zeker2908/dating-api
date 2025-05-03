package ru.zeker.authenticationservice.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import ru.zeker.authenticationservice.domain.model.entity.PasswordHistory;

import java.util.Set;
import java.util.UUID;


@Repository
public interface PasswordHistoryRepository extends JpaRepository<PasswordHistory, UUID> {
    Set<PasswordHistory> findAllByLocalAuthId(UUID localAuthId);

    @Modifying
    @Query("DELETE FROM PasswordHistory ph WHERE ph.id IN ("
            + "SELECT ph2.id FROM PasswordHistory ph2 "
            + "WHERE ph2.localAuth.id = :localAuthId "
            + "ORDER BY ph2.createdAt ASC LIMIT :count)")
    void deleteOldestByLocalAuthId(@Param("localAuthId") UUID localAuthId,
                                   @Param("count") int count);
}
