package ru.zeker.notification_service.service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring6.SpringTemplateEngine;
import ru.zeker.common.dto.UserRegisteredEvent;
import ru.zeker.notification_service.dto.EmailContext;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmailService {
    private final JavaMailSender javaMailSender;
    private final SpringTemplateEngine springTemplateEngine;

    @Value("${spring.mail.username}")
    private String from;

    @Value("${spring.application.url}")
    private String url;

    //TODO: сделать асинхронно и обработать исключения
    public void sendEmail(EmailContext emailContext) throws MessagingException {
        MimeMessage message = javaMailSender.createMimeMessage();
        MimeMessageHelper mimeMessageHelper = new MimeMessageHelper(message,
                MimeMessageHelper.MULTIPART_MODE_MIXED_RELATED, "UTF-8");

        Context context = new Context();
        context.setVariables(emailContext.getTemplateContext());

        String html = springTemplateEngine.process(emailContext.getTemplateLocation(), context);
        mimeMessageHelper.setTo(emailContext.getTo());
        mimeMessageHelper.setSubject(emailContext.getSubject());
        mimeMessageHelper.setText(html, true);
        log.info("Sending email to {}", emailContext.getTo());
        javaMailSender.send(message);

    }

    public EmailContext configureEmailContext(UserRegisteredEvent userRegisteredEvent) {
        Map<String, Object> templateContext = new HashMap<>();
        templateContext.put("firstName", userRegisteredEvent.getFirstName());
        templateContext.put("verificationURL", url+"/api/v1/auth/confirm?token="+userRegisteredEvent.getToken());
        return EmailContext.builder()
                .from(from)
                .to(userRegisteredEvent.getEmail())
                .subject("Email verification")
                .emailLanguage("ru")
                .displayName(userRegisteredEvent.getFirstName())
                .templateLocation("email/emailVerification.html")
                .templateContext(templateContext)
                .build();
    }

}
