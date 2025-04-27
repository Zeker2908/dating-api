package ru.zeker.authenticationservice.service;

import ru.zeker.authenticationservice.domain.model.entity.User;

import java.util.UUID;

public interface UserService {
    User findByEmail(String email);

    User findById(UUID id);

    User create(User user);

    User update(User user);

    User getCurrentUser(String username);

    void changePassword(String username, String oldPassword, String newPassword);

    void deleteById(UUID id);

    void deleteByEmail(String email);

    boolean existsByEmail(String email);
}
