    package ru.zeker.common.util;

    import com.google.common.cache.Cache;
    import io.jsonwebtoken.Claims;
    import io.jsonwebtoken.JwtParser;
    import io.jsonwebtoken.Jwts;
    import jakarta.annotation.PostConstruct;
    import lombok.Getter;
    import lombok.RequiredArgsConstructor;
    import ru.zeker.common.config.JwtProperties;

    import java.io.IOException;
    import java.security.Key;
    import java.security.KeyFactory;
    import java.security.NoSuchAlgorithmException;
    import java.security.spec.InvalidKeySpecException;
    import java.security.spec.X509EncodedKeySpec;
    import java.util.Base64;
    import java.util.Date;
    import java.util.concurrent.ExecutionException;
    import java.util.function.Function;

    @RequiredArgsConstructor
    @Getter
    public class JwtUtils {
        private final JwtProperties jwtProperties;
        private final Cache<String, Claims> claimsCache;

        private Key publicKey;
        private JwtParser jwtParser;

        @PostConstruct
        public void init() {
            try {
                if (jwtProperties.getPublicKeyPath() == null || !jwtProperties.getPublicKeyPath().exists()) {
                    throw new IllegalStateException("Приватный ключ не задан");
                }

                String publicKeyContent = new String(jwtProperties.getPublicKeyPath().getInputStream().readAllBytes());

                String publicKeyPEM = publicKeyContent
                        .replace("-----BEGIN PUBLIC KEY-----", "")
                        .replace("-----END PUBLIC KEY-----", "")
                        .replaceAll("\\s+", "");

                byte[] keyBytes = Base64.getDecoder().decode(publicKeyPEM);
                X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
                KeyFactory kf = KeyFactory.getInstance("EC");
                this.publicKey = kf.generatePublic(spec);

                this.jwtParser = Jwts.parserBuilder()
                        .setSigningKey(this.publicKey)
                        .build();

            }catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException("Алгоритм EC не поддерживается", e);
            } catch (InvalidKeySpecException e) {
                throw new IllegalStateException("Некорректный формат ключа", e);
            } catch (IllegalArgumentException | IOException e) {
                throw new IllegalStateException("Ошибка декодирования Base64", e);
            }
        }

        public Claims extractAllClaims(String token) {
            try {
                return claimsCache.get(token, ()->
                        jwtParser.parseClaimsJws(token).getBody());
            }catch (ExecutionException e){
                throw new RuntimeException("Не удалось проанализировать токен", e);
            }

        }

        public <T> T extractClaim(String token, Function<Claims, T> claimsResolver){
            final Claims claims = extractAllClaims(token);
            return claimsResolver.apply(claims);
        }

        public String extractUsername(String token){
            return extractClaim(token, Claims::getSubject);
        }

        public Date extractExpiration(String token) {
            return extractClaim(token, Claims::getExpiration);
        }

        public Date extractIssuedAt(String token) {
            return extractClaim(token, Claims::getIssuedAt);
        }

        public boolean isTokenExpired(String token) {
            return extractExpiration(token).before(new Date());
        }

        public boolean isValidUsername(String token,String username) {
            return extractUsername(token).equals(username);
        }

    }
