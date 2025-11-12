package ru.zeker.notificationservice.config;

import org.apache.kafka.clients.admin.NewTopic;
import org.apache.kafka.common.config.TopicConfig;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.kafka.config.TopicBuilder;

@Configuration
public class KafkaTopicConfig {
    @Bean
    public NewTopic emailNotificationDltTopic() {
        return TopicBuilder
                .name("email-notification-events" + ".DLT")
                .partitions(32)
                .replicas(1)
                .config(TopicConfig.RETENTION_MS_CONFIG, "604800000")
                .build();
    }
}
