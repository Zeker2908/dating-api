package ru.zeker.notification_service.component;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.kafka.annotation.KafkaListener;
import ru.zeker.common.dto.UserRegisteredEvent;

@Slf4j
@Component
public class ConsumerKafkaListeners {

    @KafkaListener(topics = "user-registered-events", groupId = "notification-service")
    public void listen(Object  message) {

            log.info("Received UserRegisteredEvent: {}", message);

    }
}
