package ru.zeker.userservice.service;

import ru.zeker.userservice.domain.model.RefreshToken;
import ru.zeker.userservice.domain.model.User;

import java.util.UUID;

public interface RefreshTokenService {
    String createRefreshToken(User user);
    RefreshToken verifyRefreshToken(String token);
    String rotateRefreshToken(RefreshToken token);

    void revokeRefreshToken(String token);

    void revokeAllUserTokens(String token);
}
