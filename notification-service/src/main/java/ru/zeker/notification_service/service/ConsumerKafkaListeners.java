package ru.zeker.notification_service.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Service;
import ru.zeker.common.dto.UserRegisteredEvent;

import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class ConsumerKafkaListeners {
    private final EmailService emailService;

    @KafkaListener(topics = "user-registered-events", groupId = "notification-service")
    void listenRegisteredEvents(List<ConsumerRecord<String, UserRegisteredEvent>> records) {
        records.forEach(r ->{
            try {
                log.info(
                        "Received message from topic={}, partition={}, offset={}",
                        r.topic(), r.partition(), r.offset()
                );
                UserRegisteredEvent message = r.value();
                log.info("Message: {}", message);
                emailService.sendEmail(emailService.configureEmailContext(message));
            } catch (Exception e) {
                log.error("Error processing message: {}", r.value(), e);
            }});
    }
}
