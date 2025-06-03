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

import java.io.IOException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
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
    public void init() {
        try {
            if (jwtProperties.getPrivateKeyPath() == null || !jwtProperties.getPrivateKeyPath().exists()) {
                throw new IllegalStateException("Приватный ключ не задан");
            }

            String privateKeyContent = new String(jwtProperties.getPrivateKeyPath().getInputStream().readAllBytes());

            String privateKeyPEM = privateKeyContent
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");

            byte[] keyBytes = Base64.getDecoder().decode(privateKeyPEM);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("EC");
            this.privateKey = kf.generatePrivate(spec);
            if (!(this.privateKey instanceof ECPrivateKey)) {
                throw new IllegalStateException("Ключ не является EC приватным ключом");
            }
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("EC алгоритм не поддерживается", e);
        } catch (InvalidKeySpecException e) {
            throw new IllegalStateException("Неверный формат ключа", e);
        } catch (IllegalArgumentException | IOException e) {
            throw new IllegalStateException("Ошибка декодирования Base64", e);
        }
    }
    public UUID extractUserId(String token){
        String id = jwtUtils.extractClaim(token, claims -> claims.get("id", String.class));
        if (id == null) throw new InvalidTokenException("Некорректный идентификатор пользователя");
        return UUID.fromString(id);
    }

    public Long extractVersion(String token){
       return jwtUtils.extractClaim(token, claims -> claims.get("version", Long.class));
    }


    public String generateAccessToken(UserDetails userDetails){
        Map<String, Object> claims = new HashMap<>();
        if(userDetails instanceof User customUserDetails){
            claims.put("id", customUserDetails.getId());
            claims.put("role", customUserDetails.getRole());
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
                .signWith(privateKey,SignatureAlgorithm.ES256)
                .compact();
    }


}
