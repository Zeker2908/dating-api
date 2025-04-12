package ru.zeker.userservice.service;

import ru.zeker.userservice.domain.model.User;

public interface UserService {
    User findByEmail(String email);

    User findById(Long id);

    User create(User user);

    User update(User user);

    void deleteById(Long id);

    void deleteByEmail(String email);

    boolean existsByEmail(String email);
}
