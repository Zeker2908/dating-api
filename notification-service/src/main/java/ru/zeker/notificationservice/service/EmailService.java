package ru.zeker.notificationservice.service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.eclipse.angus.mail.smtp.SMTPSenderFailedException;
import org.springframework.beans.factory.annotation.Value;
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
    
    // Константы для шаблонов
    private static final String EMAIL_VERIFICATION_TEMPLATE = "email/emailVerification.html";
    private static final String FORGOT_PASSWORD_TEMPLATE = "email/forgotPassword.html";
    private static final String SENDER_DISPLAY_NAME = "Dating API";

    @Value("${spring.mail.username}")
    private String from;

    @Value("${app.domain}")
    private String applicationUrl;

    @Value("${app.links.email-verification}")
    private String emailVerificationUrl;

    @Value("${app.links.password-reset}")
    private String passwordResetUrl;

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
            
            // Настройка письма
            messageHelper.setFrom(emailContext.getFrom(), SENDER_DISPLAY_NAME);
            messageHelper.setTo(emailContext.getTo());
            messageHelper.setSubject(emailContext.getSubject());
            messageHelper.setText(htmlContent, true);
            
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
     * Создает контекст для отправки письма с подтверждением регистрации
     *
     * @param userRegisteredEvent событие регистрации пользователя
     * @return настроенный контекст для отправки письма
     */
    public EmailContext configureEmailVerificationContext(EmailEvent userRegisteredEvent) {
        log.debug("Настройка контекста письма для подтверждения регистрации: {}", 
                userRegisteredEvent.getEmail());
        
        // Формирование URL для подтверждения
        String verificationUrl = buildVerificationUrl(userRegisteredEvent.getToken());
        
        return createEmailContext(
                userRegisteredEvent,
                "Подтверждение регистрации в Dating API",
                EMAIL_VERIFICATION_TEMPLATE,
                verificationUrl
        );
    }

    /**
     * Создает контекст для отправки письма с восстановлением пароля
     *
     * @param forgotPasswordEvent событие восстановления пароля
     * @return настроенный контекст для отправки письма
     */
    public EmailContext configureForgotPasswordContext(EmailEvent forgotPasswordEvent) {
        log.debug("Настройка контекста письма для восстановления пароля: {}",
                forgotPasswordEvent.getEmail());

        // Формирование URL для восстановления пароля
        String resetPasswordUrl = buildResetPasswordUrl(forgotPasswordEvent.getToken());

        return createEmailContext(
                forgotPasswordEvent,
                "Восстановление пароля в Dating API",
                FORGOT_PASSWORD_TEMPLATE,
                resetPasswordUrl
        );
    }
    
    /**
     * Общий метод для создания контекста email на основе события
     * 
     * @param event событие, инициирующее отправку email
     * @param subject тема письма
     * @param templateLocation путь к шаблону письма
     * @param actionUrl URL для действия (подтверждение регистрации, сброс пароля и т.д.)
     * @return настроенный контекст для отправки письма
     */
    private EmailContext createEmailContext(
            EmailEvent event,
            String subject,
            String templateLocation,
            String actionUrl
    ) {
        // Создание контекста для шаблона
        Map<String, Object> templateContext = new HashMap<>();
        templateContext.put("firstName", event.getFirstName());
        templateContext.put("verificationURL", actionUrl);
        templateContext.put("supportEmail", from);
        
        // Создание контекста письма
        return EmailContext.builder()
                .from(from)
                .to(event.getEmail())
                .subject(subject)
                .emailLanguage("ru")
                .displayName(event.getFirstName())
                .templateLocation(templateLocation)
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
        return applicationUrl + emailVerificationUrl + "?token=" + token;
    }
    
    /**
     * Создает URL для восстановления пароля пользователя
     *
     * @param token токен восстановления пароля
     * @return полный URL для восстановления пароля
     */
    private String buildResetPasswordUrl(String token) {
        return applicationUrl + passwordResetUrl + "?token=" + token;
    }
}
