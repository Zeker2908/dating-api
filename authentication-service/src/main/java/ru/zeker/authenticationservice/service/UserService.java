package ru.zeker.authenticationservice.service;

import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.zeker.authenticationservice.domain.model.entity.User;
import ru.zeker.authenticationservice.exception.UserAlreadyExistsException;
import ru.zeker.authenticationservice.exception.UserNotFoundException;
import ru.zeker.authenticationservice.repository.UserRepository;

import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {
    private static final String OLD_PASSWORD_MISMATCH = "Старый пароль не совпадает";
    private static final String SAME_PASSWORDS = "Новый пароль должен отличаться от старого";
    
    private final UserRepository repository;
    private final PasswordHistoryService passwordHistoryService;
    private final PasswordEncoder passwordEncoder;

    @Transactional(readOnly = true)
    public User findByEmail(String email) {
        return repository.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("Пользователь с email " + email + " не найден"));
    }

    @Transactional(readOnly = true)
    public User findById(UUID id) {
        return repository.findById(id)
                .orElseThrow(() -> new UserNotFoundException("Пользователь с ID " + id + " не найден"));
    }

    @Transactional
    public User create(@NotNull User user) {
        if (user.getPassword() == null && user.getOAuthId() == null) {
            throw new IllegalArgumentException("User должен иметь либо пароль, либо OAuthId");
        }

        if (repository.existsByEmail(user.getEmail())) {
            log.warn("Попытка создания дубликата пользователя: {}", user.getEmail());
            throw new UserAlreadyExistsException("Пользователь с email " + user.getEmail() + " уже существует");
        }

        if (user.getPassword() != null) {
           String rawPassword = user.getPassword();
           user.setPassword(passwordEncoder.encode(rawPassword));
           repository.save(user);
           passwordHistoryService.savePassword(user, rawPassword);
           log.info("Создан новый пользователь с ID: {}", user.getId());
           return user;
       } else {
           log.info("Создан новый пользователь с ID: {}", user.getId());
           return repository.save(user);
       }

    }

    @Transactional
    public User update(@NotNull User updatedUser) {
        User existingUser = repository.findById(updatedUser.getId())
                .orElseThrow(() -> new UserNotFoundException("Пользователь с ID " + updatedUser.getId() + " не найден"));
        
        if (!existingUser.getEmail().equals(updatedUser.getEmail()) &&
                repository.existsByEmail(updatedUser.getEmail())) {
            throw new UserAlreadyExistsException("Пользователь с email " + updatedUser.getEmail() + " уже существует");
        }
        
        User savedUser = repository.save(updatedUser);
        log.info("Обновлен пользователь с ID: {}", savedUser.getId());
        return savedUser;
    }

    @Transactional
    public void changePassword(String id, String oldPassword, String newPassword) {
        User user = findById(UUID.fromString(id));
        
        if (oldPassword.equals(newPassword)) {
            throw new BadCredentialsException(SAME_PASSWORDS);
        }
        
        if (!passwordEncoder.matches(oldPassword, user.getPassword())) {
            throw new AuthenticationCredentialsNotFoundException(OLD_PASSWORD_MISMATCH);
        }
        
        // Сохраняем новый пароль в истории
        passwordHistoryService.savePassword(user, newPassword);
        
        // Обновляем пароль пользователя
        user.setPassword(passwordEncoder.encode(newPassword));
        repository.save(user);
        log.info("Пароль изменен для пользователя с ID: {}", user.getId());
    }

    @Transactional
    public void deleteById(UUID id) {
        if (!repository.existsById(id)) {
            throw new UserNotFoundException("Пользователь с ID " + id + " не найден");
        }
        repository.deleteById(id);
        log.info("Удален пользователь с ID: {}", id);
    }

    @Transactional
    public void deleteByEmail(String email) {
        User user = findByEmail(email);
        repository.delete(user);
        log.info("Удален пользователь с email: {}", email);
    }

    @Transactional(readOnly = true)
    public boolean existsByEmail(String email) {
        return repository.existsByEmail(email);
    }
}
