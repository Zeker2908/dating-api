package ru.zeker.notificationservice.service.handlers;

import ru.zeker.common.dto.kafka.EmailEvent;
import ru.zeker.notificationservice.dto.EmailContext;

public interface EmailContextStrategy {
    EmailContext handle(EmailEvent event);
}
