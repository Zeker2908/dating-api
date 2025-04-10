package ru.zeker.user_service.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import ru.zeker.common.dto.UserRegisteredEvent;
import ru.zeker.user_service.domain.dto.LoginRequest;
import ru.zeker.user_service.domain.dto.RegisterRequest;
import ru.zeker.user_service.domain.dto.Tokens;
import ru.zeker.user_service.domain.model.RefreshToken;
import ru.zeker.user_service.domain.model.Role;
import ru.zeker.user_service.domain.model.User;
import ru.zeker.user_service.exception.TokenExpiredException;
import ru.zeker.user_service.exception.UserAlreadyEnableException;

import java.util.Date;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserService userService;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final RefreshTokenService refreshTokenService;
    private final KafkaProducer kafkaProducer;

    public void register(RegisterRequest request) {
        User user = User.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .role(Role.USER)
                .enabled(false)
                .build();
        userService.create(user);
        String token = jwtService.generateToken(user);
        UserRegisteredEvent userRegisteredEvent = UserRegisteredEvent.builder()
                .email(user.getEmail())
                .token(token)
                .firstName(user.getFirstName())
                .build();
        kafkaProducer.sendEmailVerification(userRegisteredEvent);
    }


    public Tokens login(LoginRequest request){
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        User user = userService.findByEmail(request.getEmail());
        String jwtToken = jwtService.generateToken(user);
        String refreshToken = refreshTokenService.createRefreshToken(user);
        return Tokens.builder()
                .token(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }

    public Tokens refreshToken(String refreshToken) {
        RefreshToken token = refreshTokenService.verifyRefreshToken(refreshToken);
        String jwtToken = jwtService.generateToken(userService.findById(token.getUserId()));
        String newRefreshToken = refreshTokenService.rotateRefreshToken(token);
        return Tokens.builder()
                .token(jwtToken)
                .refreshToken(newRefreshToken)
                .build();
    }

    public void confirmEmail(String token) {
        if(jwtService.extractExpiration(token).before(new Date())) throw new TokenExpiredException();
        User user = userService.findById(jwtService.extractUserId(token));
        if (user.isEnabled()) throw new UserAlreadyEnableException();
        user.setEnabled(true);
        userService.update(user);
    }
}
