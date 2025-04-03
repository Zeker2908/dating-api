package ru.zeker.user_service.service.imp;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.zeker.user_service.domain.model.RefreshToken;
import ru.zeker.user_service.domain.model.User;
import ru.zeker.user_service.exception.RefreshTokenExpiredException;
import ru.zeker.user_service.exception.RefreshTokenNotFoundException;
import ru.zeker.user_service.repository.RefreshTokenRepository;
import ru.zeker.user_service.service.JwtService;
import ru.zeker.user_service.service.RefreshTokenService;
import ru.zeker.user_service.service.UserService;

import java.util.Date;

@Service
@RequiredArgsConstructor
public class RefreshTokenServiceImpl implements RefreshTokenService {
    private final UserService userService;
    private final JwtService jwtService;
    private final RefreshTokenRepository refreshTokenRepository;

    @Override
    public String createRefreshToken(User user) {
        String token = jwtService.generateRefreshToken(user);
        var refreshToken = RefreshToken.builder()
                .token(token)
                .expiryDate(jwtService.extractExpiration(token))
                .user(user)
                .build();
        return refreshTokenRepository.save(refreshToken).getToken();
    }

    @Override
    public RefreshToken verifyRefreshToken(String token) {
        var refreshToken = refreshTokenRepository.findByToken(token)
                .orElseThrow(RefreshTokenNotFoundException::new);

        if (refreshToken.getExpiryDate().before(new Date())) {
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
    @Transactional
    public void deleteByUserId(Long id) {
        refreshTokenRepository.findByUserId(id).ifPresent(refreshTokenRepository::delete);
    }

}
