package ru.zeker.userservice.domain.component;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import ru.zeker.userservice.domain.model.User;
import ru.zeker.userservice.exception.OAuth2ProviderException;
import ru.zeker.userservice.repository.UserRepository;
import ru.zeker.userservice.service.JwtService;
import ru.zeker.userservice.service.OAuth2Service;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {
    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final OAuth2Service oAuth2Service;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        log.info("Сработал обработчик успешного прохождения аутентификации OAuth2: remote={}, uri={}",
                request.getRemoteAddr(), request.getRequestURI());
        try {
            OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
            log.debug("OAuth2User principal получены: authorities={}", authentication.getAuthorities());

            String provider = getOAuth2Provider(authentication);
            if (provider == null) {
                log.error("Не удалось получить OAuth2Provider");
                throw new OAuth2ProviderException("Не удалось получить OAuth2Provider");
            }
            log.info("OAuth2Provider получен: {}", provider);

            Boolean emailVerified = oAuth2User.getAttribute("email_verified");
            String email = oAuth2User.getAttribute("email");
            log.info("Обработка пользователя OAuth2: email={}, emailVerified={}", email, emailVerified);
            
            if (emailVerified == null || !emailVerified) {
                log.warn("Ошибка аутентификации OAuth2: адрес электронной почты не проверен для email={}", email);
                throw new OAuth2ProviderException("Email не верифицирован");
            }
            
            User user = userRepository.findByEmail(email).orElseGet(() -> {
                log.info("Пользователь не найден, регистрация нового пользователя с адресом электронной почты={}", email);
                return oAuth2Service.register(oAuth2User, provider);
            });
            log.debug("Пользователь разрешен: id={}, email={}, enabled={}", user.getId(), user.getEmail(), user.isEnabled());

            String accessToken = jwtService.generateToken(user);
            String refreshToken = jwtService.generateRefreshToken(user);

            String redirectUrl = "/api/v1/oauth2/success?accessToken=" + URLEncoder.encode(accessToken, StandardCharsets.UTF_8) +
                    "&refreshToken=" + URLEncoder.encode(refreshToken, StandardCharsets.UTF_8);
            log.info("Перенаправление аутентифицированного пользователя на: {}", "/api/v1/oauth2/success");
            response.sendRedirect(redirectUrl);
        } catch (Exception e) {
            log.error("Ошибка OAuth2SuccessHandler: {}", e.getMessage(), e);
            response.sendRedirect("/api/v1/oauth2/failure");
        }
    }

    private String getOAuth2Provider(Authentication authentication) {
        if (authentication instanceof OAuth2AuthenticationToken oauthToken) {
            return oauthToken.getAuthorizedClientRegistrationId();
        }
        return null;
    }
}
