package ru.zeker.notificationservice.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Service;
import ru.zeker.common.dto.EmailEvent;
import ru.zeker.notificationservice.dto.EmailContext;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

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
    
    // Константа для времени хранения ключей в Redis
    private static final Duration EVENT_EXPIRATION_TIME = Duration.ofMinutes(15);

    /**
     * Слушатель событий регистрации пользователей
     * Обрабатывает пакеты сообщений из топика 'user-registered-events'
     *
     * @param records список записей с событиями регистрации пользователей
     */
    @KafkaListener(
            topics = "user-registered-events", 
            groupId = "notification-service"
    )
    void listenRegisteredEvents(
            List<ConsumerRecord<String, EmailEvent>> records
    ) {
        processEvents(records, emailService::configureEmailVerificationContext, "регистрации");
    }

    /**
     * Слушатель событий восстановления пароля
     * Обрабатывает пакеты сообщений из топика 'forgot-password-events'
     *
     * @param records список записей с событиями восстановления пароля
     */
    @KafkaListener(
            topics = "forgot-password-events",
            groupId = "notification-service"
    )
    void listenForgotPasswordEvents(List<ConsumerRecord<String, EmailEvent>> records) {
        processEvents(records, emailService::configureForgotPasswordContext, "восстановления пароля");
    }

    /**
     * Обрабатывает список событий определенного типа
     *
     * @param records список записей Kafka
     * @param contextConfigurator функция для создания контекста email в зависимости от типа события
     * @param eventType тип события для логирования
     */
    private void processEvents(
            List<ConsumerRecord<String, EmailEvent>> records,
            Function<EmailEvent, EmailContext> contextConfigurator,
            String eventType
    ) {
        int totalRecords = records.size();
        log.info("Получен пакет из {} сообщений типа '{}'", totalRecords, eventType);

        AtomicInteger successCount = new AtomicInteger(0);
        AtomicInteger errorCount = new AtomicInteger(0);

        records.forEach(record -> {
            try {
                EmailContext emailContext = contextConfigurator.apply(record.value());
                processEmailEvent(record, emailContext, successCount, errorCount, eventType);
            } catch (Exception e) {
                errorCount.incrementAndGet();
                log.error("Ошибка при создании контекста для события {}: {}", eventType, e.getMessage(), e);
            }
        });

        log.info("Обработка пакета событий '{}' завершена. Успешно: {}, Ошибок: {}",
                eventType, successCount.get(), errorCount.get());
    }

    /**
     * Обрабатывает отдельное событие отправки email
     *
     * @param record запись из Kafka
     * @param emailContext контекст для отправки email
     * @param successCount счетчик успешных операций
     * @param errorCount счетчик ошибок
     * @param eventType тип события для логирования
     */
    private void processEmailEvent(
            ConsumerRecord<String, EmailEvent> record, 
            EmailContext emailContext, 
            AtomicInteger successCount, 
            AtomicInteger errorCount,
            String eventType
    ) {
        EmailEvent event = record.value();
        String eventKey = "event:" + event.getId();
        
        try {
            // Проверяем, не обрабатывали ли мы уже это событие
            if (Boolean.TRUE.equals(redisTemplate.opsForValue().setIfAbsent(eventKey, "processed", EVENT_EXPIRATION_TIME))) {
                log.info("Обработка события {} для пользователя: {}, partition: {}, offset: {}",
                        eventType, event.getEmail(), record.partition(), record.offset());

                // Проверка данных события
                validateEvent(event);

                // Запускаем отправку асинхронно и не блокируем текущий поток
                emailService.sendEmail(emailContext)
                    .exceptionally(ex -> {
                        log.error("Не удалось отправить письмо для события {} на адрес {}: {}",
                                eventType, event.getEmail(), ex.getMessage());
                        return null;
                    });

                log.debug("Событие {} обработано и запущена асинхронная отправка для: {}", 
                        eventType, event.getEmail());
                successCount.incrementAndGet();
            } else {
                log.warn("Событие {} с ID {} уже было обработано", eventType, event.getId());
            }
        } catch (Exception e) {
            errorCount.incrementAndGet();
            log.error("Ошибка обработки события {}: {}", eventType, e.getMessage(), e);
        }
    }
    
    /**
     * Проверяет корректность данных в событии
     *
     * @param event событие для отправки email
     * @throws IllegalArgumentException если данные события некорректны
     */
    private void validateEvent(EmailEvent event) {
        if (event == null) {
            throw new IllegalArgumentException("Событие не может быть null");
        }
        
        if (event.getEmail() == null || event.getEmail().isBlank()) {
            throw new IllegalArgumentException("Email пользователя не указан");
        }
        
        if (event.getToken() == null || event.getToken().isBlank()) {
            throw new IllegalArgumentException("Токен не указан");
        }
        
        log.debug("Данные события прошли валидацию: {}", event.getEmail());
    }
}
