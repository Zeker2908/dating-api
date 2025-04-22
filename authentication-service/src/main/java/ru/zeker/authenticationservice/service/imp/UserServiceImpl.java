package ru.zeker.authenticationservice.service.imp;

import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.zeker.authenticationservice.domain.model.entity.User;
import ru.zeker.authenticationservice.exception.UserAlreadyExistsException;
import ru.zeker.authenticationservice.exception.UserNotFoundException;
import ru.zeker.authenticationservice.repository.UserRepository;
import ru.zeker.authenticationservice.service.PasswordHistoryService;
import ru.zeker.authenticationservice.service.UserService;

import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    private static final String AUTH_NOT_FOUND = "Аутентификация не найдена";
    private static final String OLD_PASSWORD_MISMATCH = "Старый пароль не совпадает";
    private static final String SAME_PASSWORDS = "Новый пароль должен отличаться от старого";
    
    private final UserRepository repository;
    private final PasswordHistoryService passwordHistoryService;
    private final PasswordEncoder passwordEncoder;

    @Override
    @Transactional(readOnly = true)
    public User findByEmail(String email) {
        return repository.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("Пользователь с email " + email + " не найден"));
    }

    @Override
    @Transactional(readOnly = true)
    public User findById(UUID id) {
        return repository.findById(id)
                .orElseThrow(() -> new UserNotFoundException("Пользователь с ID " + id + " не найден"));
    }

    @Override
    @Transactional
    public User create(@NotNull User user) {
        if (repository.existsByEmail(user.getEmail())) {
            throw new UserAlreadyExistsException("Пользователь с email " + user.getEmail() + " уже существует");
        }

       if(user.getPassword() != null) {
           String rawPassword = user.getPassword();
           user.setPassword(passwordEncoder.encode(rawPassword));
           User savedUser = repository.save(user);

           passwordHistoryService.savePassword(savedUser, rawPassword);
       } else if (user.getOAuthId() != null) {
             repository.save(user);
       } else {
           throw new IllegalArgumentException("User должен иметь либо пароль, либо OAuthId");
       }

        log.info("Создан новый пользователь с ID: {}", user.getId());
        return user;
    }

    @Override
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

    @Override
    @Transactional(readOnly = true)
    public User getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated()) {
            return repository.findByEmail(authentication.getName())
                    .orElseThrow(() -> new UserNotFoundException("Текущий пользователь не найден в базе данных"));
        } else {
            throw new AuthenticationCredentialsNotFoundException(AUTH_NOT_FOUND);
        }
    }

    @Override
    @Transactional
    public void changePassword(String oldPassword, String newPassword) {
        User user = getCurrentUser();
        
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

    @Override
    @Transactional
    public void deleteById(UUID id) {
        if (!repository.existsById(id)) {
            throw new UserNotFoundException("Пользователь с ID " + id + " не найден");
        }
        repository.deleteById(id);
        log.info("Удален пользователь с ID: {}", id);
    }

    @Override
    @Transactional
    public void deleteByEmail(String email) {
        User user = findByEmail(email);
        repository.delete(user);
        log.info("Удален пользователь с email: {}", email);
    }

    @Override
    @Transactional(readOnly = true)
    public boolean existsByEmail(String email) {
        return repository.existsByEmail(email);
    }
}
