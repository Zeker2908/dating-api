package ru.zeker.userservice.service;

import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;
import ru.zeker.common.dto.UserRegisteredEvent;

@Service
@RequiredArgsConstructor
public class KafkaProducer {
    private final KafkaTemplate<String, Object> kafkaTemplate;

    public void sendEmailVerification(@NotNull UserRegisteredEvent userRegisteredEvent) {
        kafkaTemplate.send("user-registered-events", userRegisteredEvent);
    }
}
