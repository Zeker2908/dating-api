package ru.zeker.authenticationservice.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import ru.zeker.authenticationservice.service.UserService;
import ru.zeker.common.component.JwtUtils;
import ru.zeker.common.config.JwtProperties;

@RequiredArgsConstructor
@Configuration
public class AuthenticationConfig {
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;


    @Bean
    public UserDetailsService userDetailsService(){
        return userService::findByEmail;
    }

    @Bean
    public AuthenticationProvider authenticationProvider(UserDetailsService userDetailsService) {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder);
        return authProvider;
    }

}
