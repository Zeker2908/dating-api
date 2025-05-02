package ru.zeker.authenticationservice.controller;

import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import jakarta.ws.rs.core.HttpHeaders;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import ru.zeker.authenticationservice.domain.dto.request.ChangePasswordRequest;
import ru.zeker.authenticationservice.domain.dto.response.UserResponse;
import ru.zeker.authenticationservice.domain.mapper.UserMapper;
import ru.zeker.authenticationservice.service.RefreshTokenService;
import ru.zeker.authenticationservice.service.UserService;
import ru.zeker.common.headers.ApiHeaders;

import java.time.Duration;
import java.util.UUID;

import static ru.zeker.authenticationservice.util.CookieUtils.createRefreshTokenCookie;

@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;
    private final UserMapper userMapper;
    private final RefreshTokenService refreshTokenService;

    //TODO: добавить возможность привязать пароль для oauth пользователей

    @GetMapping("/me")
    public ResponseEntity<UserResponse> getCurrentUser(@RequestHeader(ApiHeaders.X_USER_ID_KEY) String id) {
        return ResponseEntity.ok(userMapper.toResponse(userService.findById(UUID.fromString(id))));
    }

    @PatchMapping("/me/password")
    public ResponseEntity<Void> changePassword(@RequestHeader(ApiHeaders.X_USER_ID_KEY) String id,
                                               @RequestBody @Valid ChangePasswordRequest changerPasswordRequest,
                                               @CookieValue(name = "refresh_token") String refreshToken,
                                               HttpServletResponse response) {
        userService.changePassword(id,changerPasswordRequest.getOldPassword(), changerPasswordRequest.getNewPassword());

        revokeTokenAndClearCookie(refreshToken, response);
        return ResponseEntity.noContent().build();
    }

    @DeleteMapping("/me")
    public ResponseEntity<Void> deleteCurrentUser(@RequestHeader(ApiHeaders.X_USER_ID_KEY) String id,
                                                  @CookieValue(name = "refresh_token") String refreshToken,
                                                  HttpServletResponse response) {
        userService.deleteById(UUID.fromString(id));

        revokeTokenAndClearCookie(refreshToken, response);
        return ResponseEntity.noContent().build();
    }

    private void revokeTokenAndClearCookie(String refreshToken, HttpServletResponse response) {
        refreshTokenService.revokeAllUserTokens(refreshToken);
        response.addHeader(HttpHeaders.SET_COOKIE,
                createRefreshTokenCookie("", Duration.ZERO).toString());
    }

}
