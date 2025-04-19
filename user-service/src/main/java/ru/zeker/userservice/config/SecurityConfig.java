package ru.zeker.userservice.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import ru.zeker.common.component.HeaderValidationFilter;
import ru.zeker.common.config.JwtProperties;
import ru.zeker.userservice.domain.component.OAuth2SuccessHandler;
import ru.zeker.userservice.service.UserService;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableConfigurationProperties(JwtProperties.class)
@Slf4j
public class SecurityConfig {

    private final UserService userService;
    private final OAuth2SuccessHandler oAuth2SuccessHandler;
    private final JwtProperties jwtProperties;


    /**
     * Настраивает {@link SecurityFilterChain} для конечных точек OAuth2.
     *
     * <p>Этот метод настраивает {@link SecurityFilterChain} для конечных точек OAuth2 и используется для обработки запросов аутентификации OAuth2
     *. Цепочка настроена на разрешение всех запросов к конечным точкам OAuth2, отключение защиты CSRF
     * и использование настраиваемого {@link OAuth2UserService} для обработки конечной точки с информацией о пользователе. Цепочка также настраивает
     * настраиваемый обработчик успеха и обработчик сбоев.
     *
     * <p>Цепочка настроена на использование {@link OAuth2SuccessHandler} для обработки успешных запросов аутентификации OAuth2.
     * Обработчик настроен на перенаправление пользователя на URL-адрес успеха по умолчанию после успешной
     * аутентификации.
     *
     * <p>Цепочка также настроена на использование настраиваемого обработчика сбоев для обработки сбоев аутентификации OAuth2. Обработчик
     * настроен на перенаправление пользователя на URL-адрес сбоя по умолчанию после сбоя аутентификации.
     *
     * <p>Цепочка настроена на создание сеанса для запросов аутентификации OAuth2, как того требует спецификация OAuth2.
     *
     * @param http объект {@link HttpSecurity}, используемый для настройки цепочки фильтров
     * @return настроенный {@link SecurityFilterChain}
     * @throws Exception, если при настройке цепочки фильтров возникает ошибка
     */
    @Bean
    @Order(1)
    public SecurityFilterChain oauthEndpointsFilterChain(HttpSecurity http) throws Exception {
        log.info("Настройка цепочки фильтров безопасности конечных точек OAuth2");
        http
                .securityMatcher("/oauth2/**", "/login/oauth2/**")
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> {
                    log.debug("Настройка разрешения для OAuth2 путей");
                    auth.anyRequest().permitAll();
                })
                .oauth2Login(oauth -> {
                    log.debug("Настройка конфигурации входа OAuth2");
                    oauth
                        // Используем стандартные пути для OAuth2
                        .authorizationEndpoint(endpoint -> {
                            log.debug("Настройка authorizationEndpoint: baseUri={}", "/oauth2/authorization");
                            endpoint.baseUri("/oauth2/authorization");
                        })
                        .redirectionEndpoint(endpoint -> {
                            log.debug("Настройка redirectionEndpoint: baseUri={}", "/login/oauth2/code/*");
                            endpoint.baseUri("/login/oauth2/code/*");
                        })
                        .failureUrl("/oauth2/failure")
                        .defaultSuccessUrl("/oauth2/success")
                        .userInfoEndpoint(userInfo -> {
                            log.debug("Настройка OAuth2 userInfoEndpoint с помощью пользовательского OAuth2UserService");
                            userInfo.userService(oAuth2UserService());
                        })
                        .successHandler(oAuth2SuccessHandler)
                        .failureHandler((request, response, exception) -> {
                            log.error("Ошибка при OAuth2 аутентификации: {}", exception.getMessage(), exception);
                            response.sendRedirect("/oauth2/failure");
                        });
                    log.debug("Настройка входа OAuth2 завершена");
                })
                .sessionManagement(session -> {
                    log.debug("Настройка управления сессиями для OAuth2");
                    session.sessionCreationPolicy(SessionCreationPolicy.ALWAYS);
                });
        log.info("Цепочка фильтров безопасности конечных точек OAuth2 успешно настроена");
        return http.build();
    }

    /**
     * Формирует цепочку фильтров безопасности для конечных точек аутентификации.
     *
     * <p>Конечные точки аутентификации не требуют аутентификации, поэтому для них
     * выключается CSRF-защита, а авторизация разрешается для любых запросов.
     * </p>
     *
     * @param http объект {@link HttpSecurity}, используемый для настройки цепочки фильтров
     * @return настроенный {@link SecurityFilterChain}
     * @throws Exception, если при настройке цепочки фильтров возникает ошибка
     */
    @Bean
    @Order(2)
    public SecurityFilterChain authEndpointsFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/auth/**")
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .userDetailsService(userDetailsService())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authenticationProvider(authenticationProvider());
        return http.build();
    }

    /**
     * Настраивает основную цепочку фильтров безопасности для защищенных конечных точек.
     * 
     * <p>Эта цепочка фильтров применяется ко всем запросам, которые не обрабатываются
     * цепочками фильтров OAuth2 и аутентификации. Она требует, чтобы все запросы были
     * аутентифицированы, отключает CSRF-защиту и настраивает управление сессиями
     * как STATELESS, что соответствует подходу REST API.</p>
     * 
     * <p>Цепочка также добавляет пользовательский фильтр валидации заголовков перед
     * стандартным фильтром аутентификации по имени пользователя и паролю.</p>
     *
     * @param http объект {@link HttpSecurity}, используемый для настройки цепочки фильтров
     * @return настроенный {@link SecurityFilterChain}
     * @throws Exception если при настройке цепочки фильтров возникает ошибка
     */
    @Bean
    @Order(3)
    public SecurityFilterChain mainFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                        .anyRequest().authenticated())
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(headerValidationFilter(), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService(){
        return userService::findByEmail;
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public HeaderValidationFilter headerValidationFilter() {
        return new HeaderValidationFilter(jwtProperties);
    }

    @Bean
    public OAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService() {
        log.info("Инициализация DefaultOAuth2UserService");
        return new DefaultOAuth2UserService() {
            @Override
            public OAuth2User loadUser(OAuth2UserRequest userRequest) {
                log.debug("Обработка запроса пользователя OAuth2: идентификатор регистрации={}, области действия={}, redirectUri={}",
                        userRequest.getClientRegistration().getRegistrationId(),
                        userRequest.getClientRegistration().getScopes(),
                        userRequest.getClientRegistration().getRedirectUri());
                try {
                    OAuth2User user = super.loadUser(userRequest);
                    log.debug("OAuth2User успешно загружен: атрибуты={}", user.getAttributes().keySet());
                    return user;
                } catch (Exception e) {
                    log.error("Ошибка загрузки пользователя OAuth2: {}", e.getMessage(), e);
                    throw e;
                }
            }
        };
    }
}
