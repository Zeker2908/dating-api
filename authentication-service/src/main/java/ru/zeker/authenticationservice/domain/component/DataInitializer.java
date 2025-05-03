package ru.zeker.authenticationservice.domain.component;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import ru.zeker.authenticationservice.domain.dto.request.RegisterRequest;
import ru.zeker.authenticationservice.domain.mapper.UserMapper;
import ru.zeker.authenticationservice.domain.model.entity.User;
import ru.zeker.authenticationservice.service.PasswordHistoryService;
import ru.zeker.authenticationservice.service.UserService;

import java.security.SecureRandom;

@Component
@RequiredArgsConstructor
@Slf4j
public class DataInitializer implements CommandLineRunner {
    private static final String CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()";
    private static final int STRING_LENGTH = 15;
    private static final String ANSI_GREEN = "\u001B[32m";
    private static final String ANSI_RESET = "\u001B[0m";

    private final UserService userService;
    private final PasswordHistoryService passwordHistoryService;
    private final UserMapper userMapper;
    private final PasswordEncoder passwordEncoder;

    @Value("${app.admin.username}")
    private String adminName;

    /**
     * Инициализирует администратора в системе.
     * Если администратор с данным email не существует, то создает администратора со сгенерированным паролем.
     * Логирует информацию о созданном администраторе.
     * @param args аргументы командной строки
     */
    @Override
    @Transactional
    public void run(String... args) {
        if (!userService.existsByEmail(adminName)) {
            final String password = generatePassword();
            log.info("Создание администратора с email: {}", adminName);
            RegisterRequest request = RegisterRequest.builder().email(adminName).password(password).build();

            User admin = userMapper.toAdmin(request, passwordEncoder);

            userService.create(admin);
            passwordHistoryService.create(admin, password);
            log.info("Администратор создан.");
            log.info(ANSI_GREEN + "Сгенерированный пароль: {}" + ANSI_RESET, password);
        } else {
            log.info("Пользователь администратора уже создан");
        }
    }
    /**
     * Генерирует случайный пароль из {@value #CHARACTERS} длиной {@value #STRING_LENGTH}.
     * @return сгенерированный пароль
     */
    private String generatePassword() {
        SecureRandom random = new SecureRandom();
        StringBuilder password = new StringBuilder(STRING_LENGTH);
        for (int i = 0; i < STRING_LENGTH; i++) {
            password.append(CHARACTERS.charAt(random.nextInt(CHARACTERS.length())));
        }
        return password.toString();
    }
}
