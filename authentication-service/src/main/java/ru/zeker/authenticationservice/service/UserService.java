package ru.zeker.authenticationservice.service;

import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import ru.zeker.authenticationservice.domain.dto.request.BindPasswordRequest;
import ru.zeker.authenticationservice.domain.model.entity.LocalAuth;
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

    @Transactional(propagation = Propagation.REQUIRED)
    public User create(@NotNull User user) {
        if (repository.existsByEmail(user.getEmail())) {
            log.warn("Попытка создания дубликата пользователя: {}", user.getEmail());
            throw new UserAlreadyExistsException("Пользователь с email " + user.getEmail() + " уже существует");
        }

        repository.save(user);
        log.info("Создан новый пользователь с ID: {}", user.getId());
        return user;

    }

    @Transactional(propagation = Propagation.REQUIRED)
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

    @Transactional(propagation = Propagation.REQUIRED)
    public void bindPassword(String userId, BindPasswordRequest request){
        User user = findById(UUID.fromString(userId));

        if(user.getLocalAuth()!=null){
            throw new UserAlreadyExistsException("Пользователь уже привязал пароль");
        }

        user.setLocalAuth(LocalAuth.builder()
                .user(user)
                .password(passwordEncoder.encode(request.getPassword()))
                .enabled(true)
                .build());
        repository.save(user);
        passwordHistoryService.create(user, request.getPassword());
    }

    @Transactional(propagation = Propagation.REQUIRED)
    public void changePassword(String userId, String oldPassword, String newPassword) {
        if (oldPassword.equals(newPassword)) {
            throw new BadCredentialsException(SAME_PASSWORDS);
        }

        User user = findById(UUID.fromString(userId));

        if(user.getLocalAuth()==null){
            throw new IllegalStateException("Пользователь не зарегистрирован локально");
        }

        if (!passwordEncoder.matches(oldPassword, user.getPassword())) {
            throw new AuthenticationCredentialsNotFoundException(OLD_PASSWORD_MISMATCH);
        }
        
        // Сохраняем новый пароль в истории
        passwordHistoryService.create(user, newPassword);
        
        // Обновляем пароль пользователя
        user.getLocalAuth().setPassword(passwordEncoder.encode(newPassword));
        repository.save(user);
        log.info("Пароль изменен для пользователя с ID: {}", user.getId());
    }

    @Transactional(propagation = Propagation.REQUIRED)
    public void deleteById(UUID id) {
        if (!repository.existsById(id)) {
            throw new UserNotFoundException("Пользователь с ID " + id + " не найден");
        }
        repository.deleteById(id);
        log.info("Удален пользователь с ID: {}", id);
    }

    @Transactional(propagation = Propagation.REQUIRED)
    public void deleteByEmail(String email) {
        User user = findByEmail(email);
        repository.delete(user);
        log.info("Удален пользователь с email: {}", email);
    }

    public boolean existsByEmail(String email) {
        return repository.existsByEmail(email);
    }
}
