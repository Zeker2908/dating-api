package ru.zeker.authenticationservice.service;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import ru.zeker.authenticationservice.domain.model.entity.PasswordHistory;
import ru.zeker.authenticationservice.domain.model.entity.User;
import ru.zeker.authenticationservice.exception.PasswordHistoryException;
import ru.zeker.authenticationservice.repository.PasswordHistoryRepository;

import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class PasswordHistoryService {
    private final PasswordHistoryRepository passwordHistoryRepository;
    private final PasswordEncoder passwordEncoder;
    
    @Value("${app.security.password-history.max-count:5}")
    private int maxPasswordHistoryCount;

    public Set<PasswordHistory> findAllByUserId(UUID userId) {
        return passwordHistoryRepository.findAllByLocalAuthId(userId);
    }

    @Transactional(propagation = Propagation.REQUIRED)
    public void create(User user, String rawPassword) {
        if (user.getLocalAuth() == null) {
            throw new IllegalStateException("LocalAuth не найден для пользователя");
        }
        Set<PasswordHistory> existingPasswords = findAllByUserId(user.getId());

        boolean isPasswordReused = existingPasswords.parallelStream()
                .anyMatch(history -> passwordEncoder.matches(rawPassword, history.getPassword()));

        if (isPasswordReused) {
            throw new PasswordHistoryException("Пароль уже использовался ранее. Пожалуйста, выберите другой пароль.");
        }

        PasswordHistory passwordHistory = PasswordHistory.builder()
                .localAuth(user.getLocalAuth())
                .password(passwordEncoder.encode(rawPassword))
                .build();

        passwordHistoryRepository.save(passwordHistory);

        // Ограничение количества хранимых паролей
        int size = existingPasswords.size();
        if (size >= maxPasswordHistoryCount) {
           passwordHistoryRepository.deleteOldestByLocalAuthId(user.getId(), size - maxPasswordHistoryCount + 1);
        }
    }
}
