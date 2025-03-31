package ru.zeker.user_service.service;

import ru.zeker.user_service.domain.model.User;

public interface UserService {
    User loadByEmail(String email);
    User create(User user);
}
