package com.apigateway.jwt;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JWTUtils {

    private final SecretKey key;

    private final long jwtExpirationMs;

    public JWTUtils(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.expirationMs}") long jwtExpirationMs) {

        this.key = Keys.hmacShaKeyFor(
                secret.getBytes(StandardCharsets.UTF_8)
        );
        this.jwtExpirationMs = jwtExpirationMs;
    }

    public String generateToken(String email,String username) {
        System.out.println("JWT USERNAME = " + username); 

        return Jwts.builder()
                .setSubject(email)
                .claim("username", username)
                .setIssuedAt(new Date())
                .setExpiration(
                        new Date(System.currentTimeMillis() + jwtExpirationMs)
                )
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();
    }

    public String getSubject(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    public boolean validate(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }
    public Date getExpiry(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getExpiration();
    }

}
