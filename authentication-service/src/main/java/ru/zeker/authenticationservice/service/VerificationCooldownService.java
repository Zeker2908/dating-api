package ru.zeker.authenticationservice.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
@RequiredArgsConstructor
public class VerificationCooldownService {
    private final RedisTemplate<String, String> redisTemplate;

    private static final Duration COOLDOWN_DURATION = Duration.ofSeconds(60);
    private static final String KEY_PREFIX = "verification_cooldown:";

    public boolean canResendEmail(String email) {
        String key = KEY_PREFIX + email;
        return !redisTemplate.hasKey(key);
    }

    public void updateCooldown(String email) {
        String key = KEY_PREFIX + email;
        redisTemplate.opsForValue().set(key, "locked", COOLDOWN_DURATION);
    }
}
