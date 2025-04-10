package ru.zeker.user_service.service;

import ru.zeker.user_service.domain.model.RefreshToken;
import ru.zeker.user_service.domain.model.User;

public interface RefreshTokenService {
    String createRefreshToken(User user);
    RefreshToken verifyRefreshToken(String token);
    String rotateRefreshToken(RefreshToken token);

    void revokeRefreshToken(String token);

    void revokeAllUserTokens(Long userId);
}
