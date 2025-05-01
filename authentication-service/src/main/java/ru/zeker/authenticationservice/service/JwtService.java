package ru.zeker.authenticationservice.service;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import ru.zeker.authenticationservice.domain.model.entity.User;
import ru.zeker.authenticationservice.exception.InvalidTokenException;
import ru.zeker.common.config.JwtProperties;
import ru.zeker.common.util.JwtUtils;

import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;

@Service
@RequiredArgsConstructor
public class JwtService {

    private final JwtUtils jwtUtils;
    private final JwtProperties jwtProperties;

    private Key privateKey;

    @PostConstruct
    public void init() throws NoSuchAlgorithmException, InvalidKeySpecException {
        String key = jwtProperties.getPrivateKey();
        if (!key.isEmpty()) {
            String privateKeyPEM = key
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s+", "");
            byte[] keyBytes = Base64.getDecoder().decode(privateKeyPEM);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            this.privateKey = kf.generatePrivate(spec);
        }else {
            throw new IllegalStateException("Приватный ключ RSA не задан");
        }
    }

    public UUID extractUserId(String token){
       Optional<String> id = Optional.ofNullable(jwtUtils.extractClaim(token, claims -> claims.get("id", String.class)));
        try {
            return id.map(UUID::fromString).orElseThrow(() -> new InvalidTokenException("Некорректный идентификатор пользователя"));
        } catch (IllegalArgumentException e) {
            throw new InvalidTokenException("Некорректный идентификатор пользователя");
        }
    }

    public Long extractVersion(String token){
       return jwtUtils.extractClaim(token, claims -> claims.get("version", Long.class));
    }



    public String generateAccessToken(UserDetails userDetails){
        Map<String, Object> claims = new HashMap<>();
        if(userDetails instanceof User customUserDetails){
            claims.put("id", customUserDetails.getId());
            claims.put("role", customUserDetails.getRole());
            claims.put("enabled", customUserDetails.isEnabled());
        }
        return generateToken(userDetails,claims,jwtProperties.getAccess().getExpiration());
    }

    public String generateRefreshToken(UserDetails userDetails){
        Map<String,Object> claims = new HashMap<>();
        if(userDetails instanceof User customUserDetails){
            claims.put("id", customUserDetails.getId());
        }
        return generateToken(userDetails,claims,jwtProperties.getRefresh().getExpiration());
    }

    public String generateEmailToken(UserDetails userDetails){
        Map<String,Object> claims = new HashMap<>();
        if(userDetails instanceof User customUserDetails){
            claims.put("id", customUserDetails.getId());
            claims.put("version", customUserDetails.getVersion());
        }
        return generateToken(userDetails,claims,jwtProperties.getAccess().getExpiration());
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        return userDetails.getUsername().equals(jwtUtils.extractUsername(token)) && !jwtUtils.isTokenExpired(token);
    }

    private String generateToken(UserDetails userDetails, Map<String, Object> claims, long expiration) {
        long currentTimeMillis = System.currentTimeMillis();

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(currentTimeMillis))
                .setExpiration(new Date(currentTimeMillis+expiration))
                .signWith(privateKey,SignatureAlgorithm.RS256)
                .compact();
    }


}
