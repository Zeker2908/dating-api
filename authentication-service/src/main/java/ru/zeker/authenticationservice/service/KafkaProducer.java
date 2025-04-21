package ru.zeker.authenticationservice.service;

import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;
import ru.zeker.common.dto.EmailEvent;

@Service
@RequiredArgsConstructor
public class KafkaProducer {
    private final KafkaTemplate<String, Object> kafkaTemplate;

    public void sendEmailVerification(@NotNull EmailEvent event) {
        kafkaTemplate.send("user-registered-events", event);
    }

    public void sendForgotPassword(@NotNull EmailEvent event) {
        kafkaTemplate.send("forgot-password-events", event);
    }
}
