package ru.zeker.userservice.service;

import ru.zeker.userservice.domain.model.User;

import java.util.UUID;

public interface UserService {
    User findByEmail(String email);

    User findById(UUID id);

    User create(User user);

    User update(User user);

    void deleteById(UUID id);

    void deleteByEmail(String email);

    boolean existsByEmail(String email);
}
