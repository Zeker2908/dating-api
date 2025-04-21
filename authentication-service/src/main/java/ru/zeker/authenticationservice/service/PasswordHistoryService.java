package ru.zeker.authenticationservice.service;

import ru.zeker.authenticationservice.domain.model.entity.PasswordHistory;
import ru.zeker.authenticationservice.domain.model.entity.User;

import java.util.Set;
import java.util.UUID;

public interface PasswordHistoryService {
    Set<PasswordHistory> findAllByUserId(UUID userId);
    void savePassword(User user, String rawPassword);
}
