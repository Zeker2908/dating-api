package ru.zeker.user_service.domain.component;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import ru.zeker.user_service.domain.model.Role;
import ru.zeker.user_service.domain.model.User;
import ru.zeker.user_service.service.UserService;

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
            LOGGER.info("Creating admin user with email: {}", adminName);
            User admin = User.builder()
                    .email(adminName)
                    .password(passwordEncoder.encode(password))
                    .role(Role.ADMIN)
                    .firstName(adminName)
                    .build();
            userService.create(admin);
            LOGGER.info("Admin user created successfully");
            LOGGER.info(ANSI_GREEN + "Generated admin password: {}" + ANSI_RESET, password);
        } else {
            LOGGER.info("Admin user already exists.");
        }
    }


    private boolean checkData(String username, String password) {
        return StringUtils.hasText(username) && StringUtils.hasText(password);
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
