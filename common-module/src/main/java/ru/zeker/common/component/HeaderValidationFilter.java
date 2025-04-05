package ru.zeker.common.component;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@RequiredArgsConstructor
@Component
public class HeaderValidationFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(HeaderValidationFilter.class);

    //TODO: Вынести в конфиги
    private static final List<String> EXCLUDED_PATHS = List.of(
            "/api/v1/auth/**"
    );
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {
        String requestUri = request.getRequestURI();

        if (EXCLUDED_PATHS.stream().anyMatch(pattern -> pathMatcher.match(pattern, requestUri))) {
            log.debug("Skipping header validation for {}", requestUri);
            filterChain.doFilter(request, response);
            return;
        }

        if (request.getHeader("X-User-Name") == null || request.getHeader("X-User-Role") == null) {
            log.warn("Missing security headers for {}", requestUri);
            response.sendError(HttpServletResponse.SC_GONE, "Missing security headers");
            return;
        }

        log.debug("Security headers found for {}", requestUri);
        filterChain.doFilter(request, response);
    }
}