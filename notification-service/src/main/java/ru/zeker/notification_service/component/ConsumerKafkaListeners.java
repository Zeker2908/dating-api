package ru.zeker.notification_service.component;

import lombok.extern.slf4j.Slf4j;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.springframework.stereotype.Component;
import org.springframework.kafka.annotation.KafkaListener;
import ru.zeker.common.dto.UserRegisteredEvent;

@Slf4j
@Component
public class ConsumerKafkaListeners {

    @KafkaListener(topics = "user-registered-events", groupId = "notification-service")
    void listenRegisteredEvents(ConsumerRecord<String, UserRegisteredEvent> record) {
        log.info(
                "Received message from topic={}, partition={}, offset={}",
                record.topic(), record.partition(), record.offset()
        );
        UserRegisteredEvent message = record.value();
        log.info("Message: {}", message);
    }
}
