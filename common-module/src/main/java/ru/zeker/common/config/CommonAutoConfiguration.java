package ru.zeker.common.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import ru.zeker.common.component.JwtUtils;

@Configuration
@ComponentScan(basePackages = "ru.zeker.common")
public class CommonAutoConfiguration{
}
