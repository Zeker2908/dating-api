package ru.zeker.authenticationservice.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import ru.zeker.authenticationservice.domain.dto.request.ChangerPasswordRequest;
import ru.zeker.authenticationservice.service.UserService;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;

    @GetMapping("/me")
    public ResponseEntity<Object> getCurrentUser(@RequestHeader("X-User-Name") String username) {
        return ResponseEntity.ok(userService.getCurrentUser(username));
    }

    @PatchMapping("/me/password")
    public ResponseEntity<Void> changePassword(@RequestHeader("X-User-Name") String username,
                                               @RequestBody @Valid ChangerPasswordRequest changerPasswordRequest) {
        userService.changePassword(username,changerPasswordRequest.getOldPassword(), changerPasswordRequest.getNewPassword());

        return ResponseEntity.noContent().build();
    }
}
