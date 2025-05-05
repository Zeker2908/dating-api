package ru.zeker.notificationservice.service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.eclipse.angus.mail.smtp.SMTPSenderFailedException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.FileSystemResource;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.retry.annotation.Backoff;
import org.springframework.retry.annotation.Retryable;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring6.SpringTemplateEngine;
import ru.zeker.common.dto.kafka.EmailEvent;
import ru.zeker.notificationservice.dto.EmailContext;
import ru.zeker.notificationservice.exception.EmailSendingException;
import ru.zeker.notificationservice.util.ThymeleafUtils;

import java.nio.charset.StandardCharsets;
import java.time.Year;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * Сервис для отправки электронных писем с использованием шаблонов Thymeleaf
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class EmailService {
    private final JavaMailSender javaMailSender;
    private final SpringTemplateEngine springTemplateEngine;

    @Value("${spring.mail.username}")
    private String from;

    @Value("${app.company-name:Dating Application}")
    private String companyName;

    /**
     * Асинхронно отправляет электронное письмо на основе данных контекста
     *
     * @param emailContext контекст для отправки письма (получатель, тема, шаблон, параметры)
     * @return CompletableFuture, который завершается после отправки письма
     * @throws EmailSendingException если отправка не удалась
     */
    @Retryable(
            retryFor = {EmailSendingException.class},
            maxAttempts = 3,
            backoff = @Backoff(delay = 1000, multiplier = 2, maxDelay = 10000)
    )
    @Async("emailSendingExecutor")
    public CompletableFuture<Void> sendEmail(EmailContext emailContext) {
        log.info("Подготовка к отправке письма на адрес: {}", emailContext.getTo());
        
        try {
            MimeMessage message = javaMailSender.createMimeMessage();
            MimeMessageHelper messageHelper = new MimeMessageHelper(
                    message,
                    MimeMessageHelper.MULTIPART_MODE_MIXED_RELATED, 
                    StandardCharsets.UTF_8.name()
            );

            // Подготовка контекста для шаблонизатора
            Context thymeleafContext = new Context();
            thymeleafContext.setVariables(emailContext.getTemplateContext());

            // Обработка шаблона
            String htmlContent = springTemplateEngine.process(
                    emailContext.getTemplateLocation(), 
                    thymeleafContext
            );

            String senderName = emailContext.getFromDisplayName() != null
                    ? emailContext.getFromDisplayName()
                    : "Dating API";
            
            // Настройка письма
            messageHelper.setFrom(emailContext.getFrom(), senderName);
            messageHelper.setTo(emailContext.getTo());
            messageHelper.setSubject(emailContext.getSubject());
            messageHelper.setText(htmlContent, true);
            if (emailContext.getAttachment() != null) {
                FileSystemResource file = new FileSystemResource(emailContext.getAttachment());
                messageHelper.addAttachment(file.getFilename(), file);
            }
            
            log.info("Отправка письма с темой '{}' на адрес: {}", 
                    emailContext.getSubject(), emailContext.getTo());
            
            // Отправка письма
            javaMailSender.send(message);
            
            log.info("Письмо успешно отправлено на адрес: {}", emailContext.getTo());
            return CompletableFuture.completedFuture(null);
            
        }catch (SMTPSenderFailedException e) {
            log.error("Ошибка при отправке письма на {}: {}",
                    emailContext.getTo(), e.getMessage(), e);
            throw new EmailSendingException("Ошибка при отправке письма: " + e.getMessage());
        } catch (MessagingException e) {
            log.error("Ошибка при подготовке письма для {}: {}",
                    emailContext.getTo(), e.getMessage(), e);
            throw new EmailSendingException("Ошибка при подготовке письма: " + e.getMessage());
        }
        catch (Exception e) {
            log.error("Неожиданная ошибка при отправке письма на {}: {}", 
                    emailContext.getTo(), e.getMessage(), e);
            throw new EmailSendingException("Ошибка при отправке письма: " + e.getMessage());
        }
    }
    
    /**
     * Общий метод для создания контекста email на основе события
     * 
     * @param event событие, инициирующее отправку email
     * @param subject тема письма
     * @param templateLocation путь к шаблону письма
     * @param payloadContext полезная нагрузка (ссылки подтверждение регистрации, сброс пароля и т.д.)
     * @return настроенный контекст для отправки письма
     */
    public EmailContext createEmailContext(
            EmailEvent event,
            String subject,
            String templateLocation,
            Map<String, Object> payloadContext
    ) {
        // Создание контекста для шаблона
        Map<String, Object> templateContext = new HashMap<>();
        templateContext.put(ThymeleafUtils.CURRENT_YEAR, Year.now().getValue());
        templateContext.put(ThymeleafUtils.COMPANY_NAME, companyName);
        if (payloadContext != null) {
            templateContext.putAll(payloadContext);
        }
        
        // Создание контекста письма
        return EmailContext.builder()
                .from(from)
                .to(event.getEmail())
                .subject(subject)
                .emailLanguage("ru")
                .templateLocation(templateLocation)
                .templateContext(templateContext)
                .build();
    }
}
