package ru.zeker.notificationservice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import ru.zeker.common.dto.kafka.EmailEventType;
import ru.zeker.notificationservice.service.handlers.EmailContextStrategy;
import ru.zeker.notificationservice.service.handlers.VerificationEmailContextStrategy;
import ru.zeker.notificationservice.service.handlers.ForgotPasswordEmailContextStrategy;

import java.util.HashMap;
import java.util.Map;

@Configuration
public class EmailContextStrategyConfig {

    @Bean
    public Map<EmailEventType, EmailContextStrategy> emailEventContextMap(VerificationEmailContextStrategy emailVerificationHandler,
                                                                          ForgotPasswordEmailContextStrategy forgotPasswordHandler) {
        Map<EmailEventType, EmailContextStrategy> emailEventContextMap = new HashMap<>();

        emailEventContextMap.put(EmailEventType.EMAIL_VERIFICATION, emailVerificationHandler);
        emailEventContextMap.put(EmailEventType.FORGOT_PASSWORD, forgotPasswordHandler);

        return emailEventContextMap;

    }
}
