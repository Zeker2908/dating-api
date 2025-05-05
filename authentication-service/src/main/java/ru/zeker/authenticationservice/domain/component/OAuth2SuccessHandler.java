package ru.zeker.authenticationservice.domain.component;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import ru.zeker.authenticationservice.domain.model.entity.User;
import ru.zeker.authenticationservice.exception.OAuth2ProviderException;
import ru.zeker.authenticationservice.service.JwtService;
import ru.zeker.authenticationservice.service.OAuth2Service;
import ru.zeker.authenticationservice.util.CookieUtils;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;

@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {
    private final JwtService jwtService;
    private final OAuth2Service oAuth2Service;
    private final ObjectMapper objectMapper;

    /**
     * Обработчик успешной аутентификации OAuth2.
     * <p>
     *     Если пользователь не найден, то регистрирует его.
     *     Если пользователь найден, но у него нет OAuth2 аутентификации в бд, то добавляет ее.
     *     Если пользователь найден, то генерирует токены доступа и обновления.
     *     Если аутентификация не удалась, то возвращает данные ошибки.
     * </p>
     * @param request        HTTP-запрос
     * @param response       HTTP-ответ
     * @param authentication результат аутентификации
     * @throws IOException   ошибка ввода-вывода
     */
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

            User user = oAuth2Service.processOauth2User(oAuth2User, provider);

            log.debug("Пользователь разрешен: id={}, email={}, enabled={}", user.getId(), user.getEmail(), user.isEnabled());

            String accessToken = jwtService.generateAccessToken(user);
            String refreshToken = jwtService.generateRefreshToken(user);

            ResponseCookie refreshCookie = CookieUtils.createRefreshTokenCookie(refreshToken, Duration.ofDays(7));
            response.addHeader(HttpHeaders.SET_COOKIE, refreshCookie.toString());

            response.setContentType("application/json;charset=UTF-8");
            objectMapper.writeValue(response.getWriter(), Map.of(
                    "access_token", accessToken,
                    "token_type", "Bearer"
            ));
        } catch (Exception e) {
            log.error("Ошибка OAuth2SuccessHandler: {}", e.getMessage(), e);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json;charset=UTF-8");
            objectMapper.writeValue(response.getWriter(), Map.of(
                    "error", "OAuth2 authentication прошла неудачно",
                    "message", e.getMessage()
            ));
        }
    }




    /**
     * Извлекает имя поставщика OAuth2 из указанного токена аутентификации.
     *
     * @param authentication токен аутентификации, из которого извлекается поставщик
     * @return имя поставщика OAuth2, если доступно, в противном случае null
     */
    private String getOAuth2Provider(Authentication authentication) {
        if (authentication instanceof OAuth2AuthenticationToken oauthToken) {
            return oauthToken.getAuthorizedClientRegistrationId();
        }
        return null;
    }
}
