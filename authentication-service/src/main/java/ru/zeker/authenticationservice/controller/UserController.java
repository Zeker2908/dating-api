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

    //TODO: сделать dto
    @GetMapping("/me")
    public ResponseEntity<Object> getCurrentUser() {
        return ResponseEntity.ok(userService.getCurrentUser());
    }

    @PatchMapping("/me/password")
    public ResponseEntity<Map<String,String>> changePassword(@RequestBody @Valid ChangerPasswordRequest changerPasswordRequest) {
        userService.changePassword(changerPasswordRequest.getOldPassword(), changerPasswordRequest.getNewPassword());

        Map<String,String> map = new HashMap<>();
        map.put("message", "Пароль успешно изменен");
        map.put("status", "success");

        return ResponseEntity.ok(map);
    }
}
