package ru.zeker.authenticationservice.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import ru.zeker.common.config.JwtProperties;
import ru.zeker.authenticationservice.domain.model.entity.User;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

@Service
@RequiredArgsConstructor
public class JwtService {

    private final JwtProperties jwtProperties;

    private Key signingKey;

    @PostConstruct
    public void init() {
        // Инициализируем ключ один раз при старте сервиса
        this.signingKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtProperties.getSecret()));
    }

    public String extractUsername(String token){
        return extractClaim(token, Claims::getSubject);
    }

    public UUID extractUserId(String token){
        return UUID.fromString(extractClaim(token, claims -> claims.get("id", String.class)));
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public String extractNonce(String token) {
        return extractClaim(token, claims -> claims.get("nonce", String.class));
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

    public String generateOnceVerificationToken(UserDetails userDetails){
        Map<String,Object> claims = new HashMap<>();
        if(userDetails instanceof User customUserDetails){
            claims.put("id", customUserDetails.getId());
            claims.put("nonce", UUID.randomUUID().toString());
        }
        return generateToken(userDetails,claims,jwtProperties.getAccess().getExpiration());
    }

    private String generateToken(UserDetails userDetails, Map<String, Object> claims, long expiration) {
        long currentTimeMillis = System.currentTimeMillis();

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(currentTimeMillis))
                .setExpiration(new Date(currentTimeMillis+expiration))
                .signWith(signingKey,SignatureAlgorithm.HS256)
                .compact();
    }


    public boolean isTokenValid(String token, UserDetails userDetails) {
        return userDetails.getUsername().equals(extractUsername(token)) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }


    private Claims extractAllClaims(String token){
        return Jwts
                .parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver){
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

}
