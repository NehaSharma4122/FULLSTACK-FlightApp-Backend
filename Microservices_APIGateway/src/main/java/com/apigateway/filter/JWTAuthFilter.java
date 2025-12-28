package com.apigateway.filter;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.cloud.gateway.filter.*;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.http.HttpMethod;
import com.apigateway.jwt.JWTUtils;
import com.apigateway.repository.BlacklistedTokenRepository;
import org.springframework.util.StringUtils;

@Slf4j
@Component
@RequiredArgsConstructor
public class JWTAuthFilter extends AbstractGatewayFilterFactory<Object> {

    private final JWTUtils jWTUtils;
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
                log.error("Missing Authorization Header");
                return unauthorized(exchange);
            }

            String cleanHeader = authHeader.replace("[", "").replace("]", "").replace("\"", "").trim();            
            if (!cleanHeader.toLowerCase().startsWith("bearer ")) {
                return unauthorized(exchange);
            }

            String token = authHeader.substring(7);
            try {
                if (!jWTUtils.validate(token)) {
                    log.error("JWT Validation failed for token: {}", token);
                    return unauthorized(exchange);
                }
            } catch (Exception e) {
                log.error("Error parsing JWT: {}", e.getMessage());
                return unauthorized(exchange);
            }

            return blacklistedTokenRepository.existsByToken(token)
                .flatMap(isBlacklisted -> {

                    if (Boolean.TRUE.equals(isBlacklisted)) {
                        return unauthorized(exchange);
                    }

                    var claims = jWTUtils.extractAllClaims(token);

                    var roles = (List<String>) claims.get("authorities");

                    var authorities = roles.stream()
                            .map(SimpleGrantedAuthority::new)
                            .toList();

                    var auth = new UsernamePasswordAuthenticationToken(
                            claims.get("username"),
                            null,
                            authorities
                    );

                    return chain.filter(exchange)
                            .contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth));
                });

        };
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }
}
