package ru.zeker.common.component;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.NonNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import ru.zeker.common.config.JwtProperties;

import java.io.IOException;
import java.util.List;

@Component
@RequiredArgsConstructor
public class HeaderValidationFilter extends OncePerRequestFilter {
    private static final Logger log = LoggerFactory.getLogger(HeaderValidationFilter.class);

    private final JwtProperties jwtProperties;

    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain)
            throws ServletException, IOException {

        String requestUri = request.getRequestURI();

        if (isExcludedPath(requestUri)) {
            filterChain.doFilter(request, response);
            return;
        }

        String username = request.getHeader("X-User-Name");
        String role = request.getHeader("X-User-Role");

        if (!isValidHeaders(username, role)) {
            log.warn("Invalid security headers for request: {}", requestUri);
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid security headers");
            return;
        }

        setAuthentication(username, role);

        filterChain.doFilter(request, response);
    }

    private boolean isExcludedPath(String requestUri) {
        return jwtProperties.getExcludedPaths().stream()
                .anyMatch(pattern -> pathMatcher.match(pattern, requestUri));
    }

    private boolean isValidHeaders(String username, String role) {
        return StringUtils.hasText(username) && StringUtils.hasText(role);
    }

    private void setAuthentication(String username, String role) {
        Authentication auth = new HeaderAuthenticationToken(username, role);
        SecurityContextHolder.getContext().setAuthentication(auth);
        log.debug("Set authentication for user: {}, role: {}", username, role);
    }
}