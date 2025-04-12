package ru.zeker.notificationservice.service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring6.SpringTemplateEngine;
import ru.zeker.common.dto.UserRegisteredEvent;
import ru.zeker.notificationservice.dto.EmailContext;
import ru.zeker.notificationservice.exception.EmailSendingException;

import java.nio.charset.StandardCharsets;
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

    @Value("${spring.application.url}")
    private String applicationUrl;

    /**
     * Асинхронно отправляет электронное письмо на основе данных контекста
     *
     * @param emailContext контекст для отправки письма (получатель, тема, шаблон, параметры)
     * @return CompletableFuture, который завершается после отправки письма
     * @throws EmailSendingException если отправка не удалась
     */
    @Async("asyncExecutor")
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
            
            // Настройка письма
            messageHelper.setFrom(emailContext.getFrom(), "Dating API");
            messageHelper.setTo(emailContext.getTo());
            messageHelper.setSubject(emailContext.getSubject());
            messageHelper.setText(htmlContent, true);
            
            log.info("Отправка письма с темой '{}' на адрес: {}", 
                    emailContext.getSubject(), emailContext.getTo());
            
            // Отправка письма
            javaMailSender.send(message);
            
            log.info("Письмо успешно отправлено на адрес: {}", emailContext.getTo());
            return CompletableFuture.completedFuture(null);
            
        } catch (MessagingException e) {
            log.error("Ошибка при подготовке письма для {}: {}", 
                    emailContext.getTo(), e.getMessage(), e);
            throw new EmailSendingException("Ошибка при подготовке письма: " + e.getMessage());
        } catch (Exception e) {
            log.error("Неожиданная ошибка при отправке письма на {}: {}", 
                    emailContext.getTo(), e.getMessage(), e);
            throw new EmailSendingException("Ошибка при отправке письма: " + e.getMessage());
        }
    }

    /**
     * Создает контекст для отправки письма с подтверждением регистрации
     *
     * @param userRegisteredEvent событие регистрации пользователя
     * @return настроенный контекст для отправки письма
     */
    public EmailContext configureEmailContext(UserRegisteredEvent userRegisteredEvent) {
        log.debug("Настройка контекста письма для подтверждения регистрации: {}", 
                userRegisteredEvent.getEmail());
        
        // Формирование URL для подтверждения
        String verificationUrl = buildVerificationUrl(userRegisteredEvent.getToken());
        
        // Создание контекста для шаблона
        Map<String, Object> templateContext = new HashMap<>();
        templateContext.put("firstName", userRegisteredEvent.getFirstName());
        templateContext.put("verificationURL", verificationUrl);
        templateContext.put("supportEmail", from);
        
        // Создание контекста письма
        return EmailContext.builder()
                .from(from)
                .to(userRegisteredEvent.getEmail())
                .subject("Подтверждение регистрации в Dating API")
                .emailLanguage("ru")
                .displayName(userRegisteredEvent.getFirstName())
                .templateLocation("email/emailVerification.html")
                .templateContext(templateContext)
                .build();
    }
    
    /**
     * Создает URL для подтверждения email пользователя
     *
     * @param token токен подтверждения
     * @return полный URL для подтверждения
     */
    private String buildVerificationUrl(String token) {
        return applicationUrl + "/api/v1/auth/confirm?token=" + token;
    }
}
