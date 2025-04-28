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
public class ForgotPasswordEmailContextStrategy implements EmailContextStrategy {
    private static final String FORGOT_PASSWORD_TEMPLATE = "email/forgotPassword.html";

    private final EmailService emailService;

    @Value("${app.domain:http://localhost:8080}")
    private String applicationUrl;

    @Value("${app.links.password-reset:/password-reset}")
    private String passwordResetUrl;


    @Override
    public EmailContext handle(EmailEvent event) {
        log.debug("Настройка контекста письма для восстановления пароля: {}",
                event.getEmail());

        String resetPasswordUrl = applicationUrl + passwordResetUrl + "?token=" + event.getToken();

        return emailService.createEmailContext(
                event,
                "Восстановление пароля в Dating API",
                FORGOT_PASSWORD_TEMPLATE,
                resetPasswordUrl
        );
    }
}
