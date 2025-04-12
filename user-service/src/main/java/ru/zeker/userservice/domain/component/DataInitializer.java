package ru.zeker.userservice.domain.component;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import ru.zeker.userservice.domain.model.Role;
import ru.zeker.userservice.domain.model.User;
import ru.zeker.userservice.service.UserService;

import java.security.SecureRandom;

@Component
@RequiredArgsConstructor
public class DataInitializer implements CommandLineRunner {
    private final static Logger LOGGER = LoggerFactory.getLogger(DataInitializer.class);
    private static final String CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()";
    private static final int STRING_LENGTH = 15;
    private static final String ANSI_GREEN = "\u001B[32m";
    private static final String ANSI_RESET = "\u001B[0m";

    private final UserService userService;
    private final PasswordEncoder passwordEncoder;

    @Value("${admin.username}")
    private String adminName;

    @Override
    public void run(String... args){
        if (!userService.existsByEmail(adminName)) {
            final String password = generatePassword();
            LOGGER.info("Создание администратора с email: {}", adminName);
            User admin = User.builder()
                    .email(adminName)
                    .password(passwordEncoder.encode(password))
                    .role(Role.ADMIN)
                    .firstName("Admin")
                    .enabled(true)
                    .build();
            userService.create(admin);
            LOGGER.info("Администратор создан.");
            LOGGER.info(ANSI_GREEN + "Сгенерированный пароль: {}" + ANSI_RESET, password);
        } else {
            LOGGER.info("Admin user already exists.");
        }
    }

    private String generatePassword() {
        SecureRandom random = new SecureRandom();
        StringBuilder password = new StringBuilder(STRING_LENGTH);
        for (int i = 0; i < STRING_LENGTH; i++) {
            password.append(CHARACTERS.charAt(random.nextInt(CHARACTERS.length())));
        }
        return password.toString();
    }
}
