package ru.zeker.notificationservice.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Service;
import ru.zeker.common.dto.UserRegisteredEvent;
import ru.zeker.notificationservice.dto.EmailContext;
import ru.zeker.notificationservice.exception.EmailSendingException;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Сервис для прослушивания и обработки событий Kafka
 * Обрабатывает события, связанные с регистрацией пользователей и отправкой уведомлений
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ConsumerKafkaListeners {
    private final EmailService emailService;
    private final RedisTemplate<String, String> redisTemplate;

    /**
     * Слушатель событий регистрации пользователей
     * Обрабатывает пакеты сообщений из топика 'user-registered-events'
     *
     * @param records список записей с событиями регистрации пользователей
     */
    @KafkaListener(
            topics = "user-registered-events", 
            groupId = "notification-service",
            containerFactory = "kafkaListenerContainerFactory"
    )
    void listenRegisteredEvents(
            List<ConsumerRecord<String, UserRegisteredEvent>> records
    ) {
        int totalRecords = records.size();
        log.info("Получен пакет из {} сообщений", totalRecords);
        
        AtomicInteger successCount = new AtomicInteger(0);
        AtomicInteger errorCount = new AtomicInteger(0);
        
        records.forEach(record -> {
            String eventKey = "event:" + record.value().getId();
            if(Boolean.TRUE.equals(redisTemplate.opsForValue().setIfAbsent(eventKey, "processed", Duration.ofMinutes(16)))) {
                try {
                    processUserRegistrationEvent(record);
                    successCount.incrementAndGet();
                } catch (Exception e) {
                    errorCount.incrementAndGet();
                    log.error("Ошибка обработки сообщения регистрации: {}", record.value(), e);
                }
            }else {
                log.warn("Событие регистрации {} уже было обработано", record.value().getId());
            }
        });
        
        log.info("Обработка пакета завершена. Успешно: {}, Ошибок: {}", 
                successCount.get(), errorCount.get());
    }
    
    /**
     * Обрабатывает отдельное событие регистрации пользователя
     *
     * @param record запись Kafka с событием регистрации
     * @throws EmailSendingException при ошибке отправки электронного письма
     */
    private void processUserRegistrationEvent(ConsumerRecord<String, UserRegisteredEvent> record) {
        UserRegisteredEvent event = record.value();
        log.info("Обработка события регистрации пользователя: {}, partition: {}, offset: {}", 
                event.getEmail(), record.partition(), record.offset());
        
        // Проверка данных события
        validateRegistrationEvent(event);
        
        // Настройка и отправка письма подтверждения
        EmailContext emailContext = emailService.configureEmailContext(event);
        emailService.sendEmail(emailContext)
                .exceptionally(ex -> {
                    log.error("Не удалось отправить письмо подтверждения для {}: {}", 
                            event.getEmail(), ex.getMessage());
                    return null;
                });
        
        log.info("Событие регистрации успешно обработано для: {}", event.getEmail());
    }
    
    /**
     * Проверяет корректность данных в событии регистрации
     *
     * @param event событие регистрации пользователя
     * @throws IllegalArgumentException если данные события некорректны
     */
    private void validateRegistrationEvent(UserRegisteredEvent event) {
        if (event == null) {
            throw new IllegalArgumentException("Событие регистрации не может быть null");
        }
        
        if (event.getEmail() == null || event.getEmail().isBlank()) {
            throw new IllegalArgumentException("Email пользователя не указан");
        }
        
        if (event.getToken() == null || event.getToken().isBlank()) {
            throw new IllegalArgumentException("Токен подтверждения не указан");
        }
        
        log.debug("Данные события регистрации прошли валидацию: {}", event.getEmail());
    }
}
