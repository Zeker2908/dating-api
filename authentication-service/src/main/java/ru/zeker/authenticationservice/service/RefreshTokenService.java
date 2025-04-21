package ru.zeker.authenticationservice.service;

import ru.zeker.authenticationservice.domain.model.entity.RefreshToken;
import ru.zeker.authenticationservice.domain.model.entity.User;

public interface RefreshTokenService {
    String createRefreshToken(User user);
    RefreshToken verifyRefreshToken(String token);
    String rotateRefreshToken(RefreshToken token);

    void revokeRefreshToken(String token);

    void revokeAllUserTokens(String token);
}
