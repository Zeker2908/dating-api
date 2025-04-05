package ru.zeker.common.component;

import lombok.Getter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;


@Getter
public class HeaderAuthenticationToken extends AbstractAuthenticationToken {
    private final String username;
    private final String role;

    public HeaderAuthenticationToken(String username, String role) {
        super(AuthorityUtils.createAuthorityList("ROLE_" + role));
        this.username = username;
        this.role = role;
        super.setAuthenticated(true);
    }
    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return username;
    }
}
