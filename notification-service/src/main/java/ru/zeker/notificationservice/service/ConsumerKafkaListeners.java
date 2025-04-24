package ru.zeker.notificationservice.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Service;
import ru.zeker.common.dto.EmailEvent;
import ru.zeker.notificationservice.dto.EmailContext;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

//TODO: Добавить Retry конфигурацию
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

    @Value("${app.redis.duration}")
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
        AtomicInteger successCount = new AtomicInteger(0);
        AtomicInteger errorCount = new AtomicInteger(0);

        records.forEach(record -> {
            switch (record.value().getType()){
                case EMAIL_VERIFICATION:
                    log.info("Получено событие подтверждения email: {}", record.value());
                    processEmailEvent(record, emailService::configureEmailVerificationContext, successCount, errorCount);
                    break;
                case FORGOT_PASSWORD:
                    log.info("Получено событие восстановления пароля: {}", record.value());
                    processEmailEvent(record, emailService::configureForgotPasswordContext, successCount, errorCount);
                    break;
                default:
                    log.error("Получено неизвестное событие: {}", record.value());
                    throw new IllegalArgumentException("Неизвестный тип события EmailEvent.Type: " + record.value().getType());
            }
        });

        log.info("Обработка пакета событий завершена. Успешно: {}, Ошибок: {}",
                 successCount.get(), errorCount.get());
    }


    /**
     * Обрабатывает отдельное событие отправки email
     *
     * @param record запись из Kafka
     * @param contextConfigurator функция для создания контекста для отправки email
     * @param successCount счетчик успешных операций
     * @param errorCount счетчик ошибок
     */
    private void processEmailEvent(
            ConsumerRecord<String, EmailEvent> record, 
            Function<EmailEvent, EmailContext> contextConfigurator,
            AtomicInteger successCount, 
            AtomicInteger errorCount
    ) {

        EmailEvent event = record.value();
        String eventType = event.getType().name();
        try {
            EmailContext emailContext = contextConfigurator.apply(record.value());
            String eventKey = "event:" + event.getId();

            // Проверяем, не обрабатывали ли мы уже это событие
            if (Boolean.TRUE.equals(redisTemplate.opsForValue().setIfAbsent(eventKey, "processed", Duration.ofMinutes(redisDuration)))) {
                log.info("Обработка события {} для пользователя: {}, partition: {}, offset: {}",
                        eventType, event.getEmail(), record.partition(), record.offset());

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

        } catch (RedisConnectionFailureException e){
            log.error("Redis недоступен, пропускаем обработку");
            throw e; // Retry позже
        }
        catch (Exception e) {
            errorCount.incrementAndGet();
            log.error("Ошибка обработки события {}: {}", eventType, e.getMessage(), e);
        }

    }

}
