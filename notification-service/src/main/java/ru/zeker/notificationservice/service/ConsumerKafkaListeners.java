package ru.zeker.notificationservice.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Service;
import ru.zeker.common.dto.kafka.EmailEvent;
import ru.zeker.notificationservice.dto.EmailContext;

import java.time.Duration;
import java.util.List;
import java.util.function.Function;

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

    @Value("${app.redis.duration:15}")
    private int redisDuration;


    /**
     * Слушатель событий отправки email для пользователей.
     * Обрабатывает пакеты сообщений из топика 'email-notification-events'
     *
     * @param records список записей с событиями отправки email для пользователей
     */
    @KafkaListener(
            topics = "email-notification-events",
            groupId = "notification-service",
            containerFactory = "batchEmailKafkaListenerContainerFactory"
    )
    void listenRegisteredEvents(
            List<ConsumerRecord<String, EmailEvent>> records
    ) {
        int totalRecords = records.size();
        log.info("Получен пакет из {} сообщений", totalRecords);

        records.forEach(record -> {
            switch (record.value().getType()){
                case EMAIL_VERIFICATION:
                    log.info("Получено событие подтверждения email: {}", record.value());
                    processEmailEvent(record, emailService::configureEmailVerificationContext);
                    break;
                case FORGOT_PASSWORD:
                    log.info("Получено событие восстановления пароля: {}", record.value());
                    processEmailEvent(record, emailService::configureForgotPasswordContext);
                    break;
                default:
                    log.error("Получено неизвестное событие: {}", record.value());
                    break;
            }
        });

        log.info("Обработка пакета событий завершена");
    }


    /**
     * Обрабатывает отдельное событие отправки email
     *
     * @param record запись из Kafka
     * @param contextConfigurator функция для создания контекста для отправки email
     */
    private void processEmailEvent(
            ConsumerRecord<String, EmailEvent> record, 
            Function<EmailEvent, EmailContext> contextConfigurator
    ) {

        EmailEvent event = record.value();
        String eventType = event.getType().name();
        try {
            String eventKey = "event:" + event.getId();

            // Проверяем, не обрабатывали ли мы уже это событие
            if (Boolean.TRUE.equals(redisTemplate.opsForValue().setIfAbsent(eventKey, "processed", Duration.ofMinutes(redisDuration)))) {
                log.info("Обработка события {} для пользователя: {}, partition: {}, offset: {}",
                        eventType, event.getEmail(), record.partition(), record.offset());

                EmailContext emailContext = contextConfigurator.apply(record.value());

                // Запускаем отправку асинхронно и не блокируем текущий поток
                emailService.sendEmail(emailContext).exceptionally(ex -> {
                    log.error("Ошибка отправки события {} для пользователя {}: {}", eventType, event.getEmail(), ex.getMessage());
                    return null;
                });

                log.debug("Событие {} обработано и запущена асинхронная отправка для: {}",
                        eventType, event.getEmail());
            } else {
                log.warn("Событие {} с ID {} уже было обработано", eventType, event.getId());
            }

        } catch (RedisConnectionFailureException e){
            log.error("Redis недоступен");
            throw e;
        }
        catch (Exception e) {
            log.error("Ошибка обработки события {}: {}", eventType, e.getMessage(), e);
        }

    }

}
