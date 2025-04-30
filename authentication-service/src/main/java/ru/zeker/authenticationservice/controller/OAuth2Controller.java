package ru.zeker.authenticationservice.controller;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import ru.zeker.authenticationservice.domain.dto.response.AuthenticationResponse;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

import static ru.zeker.authenticationservice.util.CookieUtils.createRefreshTokenCookie;

@RestController
@RequestMapping("/oauth2")
public class OAuth2Controller {
    @GetMapping("/success")
    public ResponseEntity<AuthenticationResponse> success(@RequestParam String accessToken, @RequestParam String refreshToken,
                                                          HttpServletResponse response) {

        String decodedAccessToken = URLDecoder.decode(accessToken, StandardCharsets.UTF_8);
        String decodedRefreshToken = URLDecoder.decode(refreshToken, StandardCharsets.UTF_8);

        AuthenticationResponse authenticationResponse = new AuthenticationResponse(decodedAccessToken);
        ResponseCookie cookie = createRefreshTokenCookie(decodedRefreshToken, Duration.ofDays(7));
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());

        return ResponseEntity.ok(authenticationResponse);
    }

    @GetMapping("/failure")
    public ResponseEntity<Void> failure() {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
}
