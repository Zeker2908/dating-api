package ru.zeker.user_service.service.imp;

import jakarta.ws.rs.NotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import ru.zeker.user_service.domain.model.RefreshToken;
import ru.zeker.user_service.domain.model.User;
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
        refreshTokenRepository.save(refreshToken);
        return refreshToken.getToken();
    }

    //TODO: сделать кастомные эксепшены
    @Override
    public RefreshToken verifyRefreshToken(String token) {
        var refreshToken = refreshTokenRepository.findByToken(token).orElseThrow(()->new NotFoundException("Invalid refresh token"));
        if(refreshToken.getExpiryDate().before(new Date())){
            refreshTokenRepository.delete(refreshToken);
            throw new NotFoundException("Invalid refresh token");
        }
        return refreshToken;
    }

    @Override
    public String rotateRefreshToken(RefreshToken token) {
        refreshTokenRepository.delete(token);
        return createRefreshToken(token.getUser());
    }

    @Override
    public void deleteByUser(User user) {
        var token = refreshTokenRepository.findByUser(user).orElseThrow(()->new NotFoundException("Refresh token not found"));
        refreshTokenRepository.delete(token);
    }
}
