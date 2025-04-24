package ru.zeker.authenticationservice.service.imp;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.zeker.authenticationservice.domain.model.entity.PasswordHistory;
import ru.zeker.authenticationservice.domain.model.entity.User;
import ru.zeker.authenticationservice.repository.PasswordHistoryRepository;
import ru.zeker.authenticationservice.service.PasswordHistoryService;

import java.util.Comparator;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class PasswordHistoryServiceImpl implements PasswordHistoryService {
    private final PasswordHistoryRepository passwordHistoryRepository;
    private final PasswordEncoder passwordEncoder;
    
    @Value("${app.security.password-history.max-count:5}")
    private int maxPasswordHistoryCount;

    @Override
    public Set<PasswordHistory> findAllByUserId(UUID userId) {
        return passwordHistoryRepository.findAllByUserId(userId);
    }

    @Override
    @Transactional
    public void savePassword(User user, String rawPassword) {
        // Проверка на повторное использование пароля
        Set<PasswordHistory> existingPasswords = findAllByUserId(user.getId());
        boolean isPasswordReused = false;

        if(!existingPasswords.isEmpty()){
            isPasswordReused = existingPasswords.stream()
                    .anyMatch(history -> passwordEncoder.matches(rawPassword, history.getPassword()));

        }
        if (isPasswordReused) {
            throw new IllegalArgumentException("Пароль уже использовался ранее. Пожалуйста, выберите другой пароль.");
        }
        
        // Создание новой записи истории
        PasswordHistory passwordHistory = PasswordHistory.builder()
                .user(user)
                .password(passwordEncoder.encode(rawPassword))
                .build();
        
        passwordHistoryRepository.save(passwordHistory);
        
        // Ограничение количества хранимых паролей
        if (existingPasswords.size() >= maxPasswordHistoryCount) {
            removeOldestPasswords(user.getId(), existingPasswords.size() - maxPasswordHistoryCount + 1);
        }
    }

    private void removeOldestPasswords(UUID userId, int countToRemove) {
        Set<PasswordHistory> passwordsToRemove = findAllByUserId(userId).stream()
                .sorted(Comparator.comparing(PasswordHistory::getCreatedAt))
                .limit(countToRemove)
                .collect(Collectors.toSet());
        
        passwordHistoryRepository.deleteAll(passwordsToRemove);
    }
}
