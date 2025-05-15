package com.example.authservice.service;

import com.example.authservice.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration-ms}")
    private long expiration;

    private SecretKey key;
    private JwtParser parser;

    @PostConstruct
    private void init() {
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        this.key = Keys.hmacShaKeyFor(keyBytes);
        this.parser = Jwts.parser().setSigningKey(key).build();
    }

    /**
     * Извлечение имени пользователя из токена
     *
     * @param token токен
     * @return имя пользователя
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Извлечение данных из токена
     *
     * @param token          токен
     * @param claimsResolver функция извлечения данных
     * @param <T>            тип данных
     * @return данные
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = parser.parseClaimsJws(token).getBody();
        return claimsResolver.apply(claims);
    }

    /**
     * Генерация токена
     *
     * @param user данные пользователя
     * @return токен
     */
    public String generateToken(User user) {
        return Jwts.builder()
                .subject(user.getUsername())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + expiration))
                .claims(Map.of("role", user.getRole().getName()))
                .signWith(key)
                .compact();
    }

    /**
     * Проверка токена на валидность
     *
     * @param token токен
     * @param user  данные пользователя
     * @return true, если токен валиден
     */
    public boolean isTokenValid(String token, User user) {
        final String username = extractUsername(token);
        return username.equals(user.getUsername()) && !isTokenExpired(token);
    }

    /**
     * Проверка токена на просроченность
     *
     * @param token токен
     * @return true, если токен просрочен
     */
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    /**
     * Извлечение даты истечения токена
     *
     * @param token токен
     * @return дата истечения
     */
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }
}
