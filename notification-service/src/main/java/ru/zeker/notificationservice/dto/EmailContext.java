package ru.zeker.notificationservice.dto;

import lombok.Builder;
import lombok.Data;

import java.util.Map;

@Data
@Builder
public class EmailContext {
    private String from;
    private String to;
    private String subject;
    private String attachment;
    private String fromDisplayName;
    private String emailLanguage;
    private String displayName;
    private String templateLocation;
    private Map<String, Object> templateContext;
}
