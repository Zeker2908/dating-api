package ru.zeker.common.component;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import ru.zeker.common.config.JwtProperties;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

@Component
@RequiredArgsConstructor
public class HeaderValidationFilter extends OncePerRequestFilter {

    private final JwtProperties jwtProperties;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain)
            throws ServletException, IOException {

        String username = request.getHeader("X-User-Name");
        String role = request.getHeader("X-User-Role");
        String signature = request.getHeader("X-User-Signature");

        try {
            if (!isValidHeaders(username, role, signature)) {
                filterChain.doFilter(request, response);
                return;
            }
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN);
            throw new RuntimeException(e);
        }

        setAuthentication(username, role);

        filterChain.doFilter(request, response);
    }


    private boolean isValidHeaders(String username, String role, String signature) throws NoSuchAlgorithmException, InvalidKeyException {
        return StringUtils.hasText(username) && StringUtils.hasText(role) &&
                (StringUtils.hasText(signature) &&
                        HmacUtil.verify(username + "|" + role, signature, jwtProperties.getSecretHeader(),"HmacSHA256"));
    }

    private void setAuthentication(String username, String role) {
        Authentication auth = new HeaderAuthenticationToken(username, role);
        SecurityContextHolder.getContext().setAuthentication(auth);
    }
}