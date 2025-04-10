package ru.zeker.user_service.service.imp;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import ru.zeker.user_service.domain.model.RefreshToken;
import ru.zeker.user_service.domain.model.User;
import ru.zeker.user_service.exception.TokenExpiredException;
import ru.zeker.user_service.exception.TokenNotFoundException;
import ru.zeker.user_service.repository.RefreshTokenRepository;
import ru.zeker.user_service.service.JwtService;
import ru.zeker.user_service.service.RefreshTokenService;
import ru.zeker.user_service.service.UserService;

import java.util.Date;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class RefreshTokenServiceImpl implements RefreshTokenService {
    private final JwtService jwtService;
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserService userService;

    @Override
    public String createRefreshToken(User user) {
        String token = jwtService.generateRefreshToken(user);
        Date expiryDate = jwtService.extractExpiration(token);

        RefreshToken refreshToken = RefreshToken.builder()
                .token(token)
                .userId(user.getId())
                .revoked(false)
                .expiryDate(expiryDate)
                .ttl(TimeUnit.MILLISECONDS.toSeconds(expiryDate.getTime() - System.currentTimeMillis()))
                .build();

        return refreshTokenRepository.save(refreshToken).getToken();
    }

    @Override
    public RefreshToken verifyRefreshToken(String token) {
        return refreshTokenRepository.findByToken(token)
                .map(t -> {
                    if (t.getRevoked() || t.getExpiryDate().before(new Date(System.currentTimeMillis()))) {
                        refreshTokenRepository.delete(t);
                        throw new TokenExpiredException("Token expired or revoked");
                    }
                    return t;
                })
                .orElseThrow(TokenNotFoundException::new);
    }

    @Override
    public String rotateRefreshToken(RefreshToken token) {
        refreshTokenRepository.delete(token);
        return createRefreshToken(userService.findById(token.getUserId()));
    }

    @Override
    public void revokeRefreshToken(String token) {
        refreshTokenRepository.findByToken(token)
                .ifPresent(t -> {
                    t.setRevoked(true);
                    refreshTokenRepository.save(t);
                });
    }

    @Override
    public void revokeAllUserTokens(Long userId) {
        refreshTokenRepository.findAllByUserId(userId)
                .forEach(t -> {
                    t.setRevoked(true);
                    refreshTokenRepository.save(t);
                });
    }
}
