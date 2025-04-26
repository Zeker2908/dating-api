package ru.zeker.notificationservice.service.handlers;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import ru.zeker.common.dto.kafka.EmailEvent;
import ru.zeker.notificationservice.dto.EmailContext;
import ru.zeker.notificationservice.service.EmailService;

@Component
@Slf4j
@RequiredArgsConstructor
public class VerificationEmailContextStrategy implements EmailContextStrategy {
    private static final String EMAIL_VERIFICATION_TEMPLATE = "email/emailVerification.html";

    private final EmailService emailService;

    @Value("${app.domain}")
    private String applicationUrl;

    @Value("${app.links.email-verification}")
    private String emailVerificationUrl;

    @Override
    public EmailContext handle(EmailEvent event) {
        log.debug("Настройка контекста письма для подтверждения регистрации: {}",
                event.getEmail());

        String verificationUrl = applicationUrl + emailVerificationUrl + "?token=" + event.getToken();

        return emailService.createEmailContext(
                event,
                "Подтверждение регистрации в Dating API",
                EMAIL_VERIFICATION_TEMPLATE,
                verificationUrl
        );
    }

}
