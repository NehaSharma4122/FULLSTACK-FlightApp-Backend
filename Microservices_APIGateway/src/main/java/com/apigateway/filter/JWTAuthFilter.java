package com.apigateway.filter;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

import org.springframework.http.HttpStatus;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.stereotype.Component;

import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;

import com.apigateway.jwt.JWTUtils;
import com.apigateway.repository.BlacklistedTokenRepository;

import java.util.Collections;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class JWTAuthFilter extends AbstractGatewayFilterFactory<Object> {

    private final JWTUtils jwtUtils;
    private final BlacklistedTokenRepository blacklistedTokenRepository;

    @Override
    public GatewayFilter apply(Object config) {

        return (exchange, chain) -> {
            if (exchange.getRequest().getMethod() == HttpMethod.OPTIONS) {
                return chain.filter(exchange);
            }
            String authHeader = exchange.getRequest()
                    .getHeaders()
                    .getFirst(HttpHeaders.AUTHORIZATION);

            if (!StringUtils.hasText(authHeader)) {
                log.error("Missing Authorization header");
                return unauthorized(exchange);
            }

            String cleanHeader = authHeader
                    .replace("[", "")
                    .replace("]", "")
                    .replace("\"", "")
                    .trim()
                    .replaceAll("\\s+", " ");

            if (!cleanHeader.toLowerCase().startsWith("bearer ")) {
                log.error("Invalid Authorization header format: {}", cleanHeader);
                return unauthorized(exchange);
            }

            String token = cleanHeader.substring(7).trim();

            try {
                if (!jwtUtils.validate(token)) {
                    log.error("JWT validation failed");
                    return unauthorized(exchange);
                }
            } catch (Exception e) {
                log.error("Error validating JWT: {}", e.getMessage());
                return unauthorized(exchange);
            }

            return blacklistedTokenRepository.existsByToken(token)
                    .flatMap(isBlacklisted -> {

                        if (Boolean.TRUE.equals(isBlacklisted)) {
                            log.error("Rejected blacklisted token");
                            return unauthorized(exchange);
                        }

                        try {
                            var claims = jwtUtils.extractAllClaims(token);

                            String username = claims.get("username", String.class);

                            if (!StringUtils.hasText(username)) {
                                log.error("Username missing in JWT claims");
                                return unauthorized(exchange);
                            }

                            // Prefer authorities[] if present
                            List<String> claimAuthorities =
                                    claims.get("authorities", List.class);

                            String role;

                            if (claimAuthorities != null && !claimAuthorities.isEmpty()) {
                                role = claimAuthorities.get(0);
                            } else {
                                role = claims.get("role", String.class);
                            }

                            if (!StringUtils.hasText(role)) {
                                role = "ROLE_USER";
                            }

                            if (!role.startsWith("ROLE_")) {
                                role = "ROLE_" + role;
                            }

                            var authorities =
                                    Collections.singletonList(new SimpleGrantedAuthority(role));

                                    // ========= ROLE-BASED ACCESS CONTROL (RBAC) =========
                            String path = exchange.getRequest().getPath().value();
                            String method = exchange.getRequest().getMethod() != null
                                    ? exchange.getRequest().getMethod().name()
                                    : "UNKNOWN";

                            log.info("REQUEST {} {} — user={} role={}", method, path, username, role);

                            // ================= ADMIN-ONLY =================
                            if (path.startsWith("/api/flight/airline")) {

                                if (!role.equals("ROLE_ADMIN")) {
                                    log.error("ACCESS BLOCKED — USER attempted ADMIN endpoint {}", path);

                                    // 🔥 IMPORTANT — STOP REQUEST HERE 🔥
                                    return unauthorized(exchange);
                                }
                            }

                            var authentication =
                                    new UsernamePasswordAuthenticationToken(
                                            username,
                                            null,
                                            authorities
                                    );

                            return chain.filter(exchange)
                                    .contextWrite(
                                            ReactiveSecurityContextHolder.withAuthentication(authentication));

                        } catch (Exception e) {
                            log.error("Failed to process JWT claims: {}", e.getMessage());
                            return unauthorized(exchange);
                        }
                    });
        };
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }
}
