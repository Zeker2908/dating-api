package ru.zeker.notificationservice.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;
import ru.zeker.common.dto.kafka.EmailEvent;
import ru.zeker.common.dto.kafka.EmailEventType;
import ru.zeker.notificationservice.dto.EmailContext;
import ru.zeker.notificationservice.service.handlers.EmailContextStrategy;

import java.time.Duration;
import java.util.Map;

/**
 * Сервис для прослушивания и обработки событий Kafka.
 * Обрабатывает события, связанные с регистрацией пользователей и отправкой уведомлений
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ConsumerKafkaListeners {
    private final EmailService emailService;
    private final RedisTemplate<String, String> redisTemplate;
    private final Map<EmailEventType, EmailContextStrategy> emailEventContextMap;
    private final KafkaTemplate<String, Object> kafkaTemplate;

    @Value("${app.redis.duration:15}")
    private int redisDuration;


    /**
     * Слушатель событий отправки email для пользователей.
     * Обрабатывает пакеты сообщений из топика 'email-notification-events'
     *
     * @param record список записей с событиями отправки email для пользователей
     */
    @KafkaListener(
            topics = "email-notification-events",
            containerFactory = "emailKafkaListenerContainerFactory"
    )
    void listenRegisteredEvents(
            ConsumerRecord<String, EmailEvent> record
    ) {
        log.info("Получено сообщение");

        handleRecord(record);

        log.info("Обработка события завершена");
    }

    /**
     * Обрабатывает отдельную запись из Kafka с событием отправки email.
     * <p>
     * Выполняет валидацию события, определяет стратегию обработки по типу события,
     * и инициирует дальнейшую обработку события. Если событие некорректно или не поддерживается,
     * запись логируется и дальнейшая обработка не производится.
     *
     * @param record запись из Kafka, содержащая событие {@link EmailEvent}
     */
    private void handleRecord(ConsumerRecord<String, EmailEvent> record) {
        EmailEvent event = record.value();
        if (event == null) {
            log.warn("Пустое событие в записи Kafka: partition={}, offset={}", record.partition(), record.offset());
            return;
        }

        EmailContextStrategy contextStrategy = emailEventContextMap.get(event.getType());
        if (contextStrategy == null) {
            log.error("Неизвестное событие: {}", event.getType());
            return;
        }

        processEmailEvent(record, contextStrategy.handle(event));
    }


    /**
     * Обрабатывает отдельное событие отправки email
     *
     * @param record       запись из Kafka
     * @param emailContext контекст для отправки email
     */
    private void processEmailEvent(
            ConsumerRecord<String, EmailEvent> record,
            EmailContext emailContext
    ) {

        EmailEvent event = record.value();
        String eventType = event.getType().name();
        try {
            String eventKey = "event:" + event.getId();

            // Проверяем, не обрабатывали ли мы уже это событие
            if (Boolean.TRUE.equals(redisTemplate.opsForValue().setIfAbsent(eventKey, "processed", Duration.ofMinutes(redisDuration)))) {
                log.info("Обработка события {} для пользователя: {}, partition: {}, offset: {}",
                        eventType, event.getEmail(), record.partition(), record.offset());

                // Запускаем отправку асинхронно и не блокируем текущий поток
                emailService.sendEmail(emailContext).exceptionally(ex -> {
                    log.error("Ошибка отправки события {} для пользователя {}: {}", eventType, event.getEmail(), ex.getMessage());
                    sendToDeadLetterTopic(record);
                    return null;
                });

                log.debug("Событие {} обработано и запущена асинхронная отправка для: {}",
                        eventType, event.getEmail());
            } else {
                log.warn("Событие {} с ID {} уже было обработано", eventType, event.getId());
            }

        } catch (RedisConnectionFailureException e) {
            log.error("Redis недоступен");
            throw e;
        } catch (Exception e) {
            log.error("Ошибка обработки события {}: {}", eventType, e.getMessage(), e);
        }

    }

    private void sendToDeadLetterTopic(ConsumerRecord<String, EmailEvent> record) {
        try {
            String dltTopic = record.topic() + ".DLT";
            kafkaTemplate.send(dltTopic, record.key(), record.value());
            log.warn("Сообщение отправлено в Dead Letter Topic: {}", dltTopic);
        } catch (Exception e) {
            log.error("Не удалось отправить в DLT: {}", e.getMessage(), e);
        }
    }


}
