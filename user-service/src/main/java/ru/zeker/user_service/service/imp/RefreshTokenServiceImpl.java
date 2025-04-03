package ru.zeker.user_service.service.imp;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import ru.zeker.user_service.domain.model.RefreshToken;
import ru.zeker.user_service.domain.model.User;
import ru.zeker.user_service.exception.RefreshTokenExpiredException;
import ru.zeker.user_service.exception.RefreshTokenNotFoundException;
import ru.zeker.user_service.repository.RefreshTokenRepository;
import ru.zeker.user_service.service.JwtService;
import ru.zeker.user_service.service.RefreshTokenService;

import java.util.Date;
import java.util.List;

@Service
@RequiredArgsConstructor
public class RefreshTokenServiceImpl implements RefreshTokenService {
    private final JwtService jwtService;
    private final RefreshTokenRepository refreshTokenRepository;

    @Override
    public String createRefreshToken(User user) {
        refreshTokenRepository.findByUserId(user.getId()).ifPresent(refreshTokenRepository::delete);
        String token = jwtService.generateRefreshToken(user);
        var refreshToken = RefreshToken.builder()
                .token(token)
                .expiryDate(jwtService.extractExpiration(token))
                .user(user)
                .revoked(false)
                .build();
        return refreshTokenRepository.save(refreshToken).getToken();
    }

    @Override
    public RefreshToken verifyRefreshToken(String token) {
        var refreshToken = refreshTokenRepository.findByToken(token)
                .orElseThrow(RefreshTokenNotFoundException::new);

        if (refreshToken.getExpiryDate().before(new Date()) || refreshToken.getRevoked()) {
            refreshTokenRepository.delete(refreshToken);
            throw new RefreshTokenExpiredException();
        }
        return refreshToken;
    }

    @Override
    public String rotateRefreshToken(RefreshToken token) {
        User user = token.getUser();
        refreshTokenRepository.delete(token);
        return createRefreshToken(user);
    }

    @Override
    public void revokeRefreshToken(String token) {
        var refreshToken = refreshTokenRepository.findByToken(token).orElseThrow(RefreshTokenNotFoundException::new);
        refreshToken.setRevoked(true);
        refreshTokenRepository.save(refreshToken);
    }

    //TODO: Реализовать для админа
    @Override
    public void revokeAllUserTokens(Long userId) {
        List<RefreshToken> tokens = refreshTokenRepository.findAllByUserId(userId);
        tokens.forEach(token -> token.setRevoked(true));
        refreshTokenRepository.saveAll(tokens);
    }
}
