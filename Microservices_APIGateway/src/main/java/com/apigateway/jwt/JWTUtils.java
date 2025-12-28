package com.apigateway.jwt;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.apigateway.entity.Role;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;

@Slf4j
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
        System.out.println("AUTH SERVICE SECRET = " + secret);
        log.info("=== JWT INITIALIZED ===");
        log.info("SECRET LENGTH: {} chars", secret.length());
        log.info("KEY ALGORITHM: {}", key.getAlgorithm());
        log.info("EXPIRATION (ms): {}", jwtExpirationMs);
        log.info("=======================");
    }

public String generateToken(String email, String username, Role role) {

        log.info("GENERATING TOKEN");
        log.info(" subject(email) = {}", email);
        log.info(" username = {}", username);
        log.info(" role = {}", role.name());

        Date issuedAt = new Date();
        Date expiry = new Date(System.currentTimeMillis() + jwtExpirationMs);

        log.info(" issuedAt = {}", issuedAt);
        log.info(" expiry   = {}", expiry);

        String token = Jwts.builder()
                .setSubject(email)
                .claim("username", username)
                .claim("authorities", List.of(role.name()))
                .setIssuedAt(issuedAt)
                .setExpiration(expiry)
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();

        log.info("TOKEN GENERATED (first 25 chars) = {}...", token.substring(0, 25));

        return token;
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

        log.info("=== VALIDATING TOKEN ===");
        log.info(" token(first 25) = {}...", safeTrim(token));

        try {
            Jws<Claims> parsed = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token);

            Date exp = parsed.getBody().getExpiration();
            Date iat = parsed.getBody().getIssuedAt();

            log.info(" VALIDATION SUCCESS");
            log.info(" subject  = {}", parsed.getBody().getSubject());
            log.info(" issuedAt = {}", iat);
            log.info(" expires  = {}", exp);

            if (exp.before(new Date())) {
                log.error(" TOKEN EXPIRED at {}", exp);
                return false;
            }

            return true;

        } catch (ExpiredJwtException e) {
            log.error("❌ JWT EXPIRED — exp = {}", e.getClaims().getExpiration());
        } catch (io.jsonwebtoken.security.SignatureException e) {
            log.error("❌ INVALID SIGNATURE — Secret key mismatch");
        } catch (MalformedJwtException e) {
            log.error("❌ MALFORMED TOKEN");
        } catch (UnsupportedJwtException e) {
            log.error("❌ UNSUPPORTED TOKEN FORMAT");
        } catch (IllegalArgumentException e) {
            log.error("❌ EMPTY OR NULL TOKEN");
        } catch (Exception e) {
            log.error("❌ UNKNOWN JWT ERROR = {}", e.getMessage(), e);
        }

        return false;
    }
    
    public Claims extractAllClaims(String token) {

        log.info("EXTRACTING CLAIMS (first 25) = {}...", safeTrim(token));

        Claims claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();

        log.info(" CLAIMS LOADED:");
        log.info("  subject  = {}", claims.getSubject());
        log.info("  username = {}", claims.get("username"));
        log.info("  authorities = {}", claims.get("authorities"));
        log.info("  issuedAt = {}", claims.getIssuedAt());
        log.info("  expires  = {}", claims.getExpiration());

        return claims;
    }

    public Date getExpiry(String token) {
        return extractAllClaims(token).getExpiration();
    }
    private String safeTrim(String token) {
        if (token == null) return "null";
        return token.length() <= 25 ? token : token.substring(0, 25);
    }

}