package ru.zeker.notificationservice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.*;

@Configuration
public class AsyncConfig {
    @Bean(name = "emailSendingExecutor")
    public Executor emailSendingExecutor() {
        return Executors.newVirtualThreadPerTaskExecutor();
    }
}
