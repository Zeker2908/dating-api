package ru.zeker.notification_service.component;

import jakarta.mail.MessagingException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Service;
import ru.zeker.common.dto.UserRegisteredEvent;
import ru.zeker.notification_service.service.EmailService;

@Slf4j
@Service
@RequiredArgsConstructor
public class ConsumerKafkaListeners {
    private final EmailService emailService;

    @KafkaListener(topics = "user-registered-events", groupId = "notification-service")
    void listenRegisteredEvents(ConsumerRecord<String, UserRegisteredEvent> record) throws MessagingException {
        try {
            log.info(
                    "Received message from topic={}, partition={}, offset={}",
                    record.topic(), record.partition(), record.offset()
            );
            UserRegisteredEvent message = record.value();
            log.info("Message: {}", message);
            emailService.sendEmail(emailService.configureEmailContext(message));
        } catch (Exception e) {
            log.error("Error processing message: {}", record.value(), e);
        }
    }
}
