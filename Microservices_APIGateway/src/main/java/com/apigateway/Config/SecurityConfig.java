package com.apigateway.Config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtGrantedAuthoritiesConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain securityFilterChain(ServerHttpSecurity http) {

    	return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .cors(Customizer.withDefaults())
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                        .pathMatchers("/api/auth/**").permitAll()
                        .pathMatchers("/microservice-flightservice/api/flight/airline/**").hasAuthority("ROLE_ADMIN")
                        .pathMatchers("/microservice-bookingservice/api/flight/booking/**").hasAuthority("ROLE_USER")
                        .pathMatchers("/microservice-flightservice/api/flight/search").hasAnyAuthority("ROLE_USER", "ROLE_ADMIN")
                        .pathMatchers("/microservice-bookingservice/api/flight/ticket/**").hasAnyAuthority("ROLE_USER", "ROLE_ADMIN")
                        .anyExchange().authenticated()                        
                
            )
                .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // @Bean
    // public ReactiveJwtAuthenticationConverter jwtAuthenticationConverter() {
    //     JwtGrantedAuthoritiesConverter authoritiesConverter = new JwtGrantedAuthoritiesConverter();
    //     authoritiesConverter.setAuthoritiesClaimName("authorities"); // Tell it to look at our "role" claim
    //     authoritiesConverter.setAuthorityPrefix(""); 

    //     ReactiveJwtAuthenticationConverter converter = new ReactiveJwtAuthenticationConverter();
    //     converter.setJwtGrantedAuthoritiesConverter(new ReactiveJwtGrantedAuthoritiesConverterAdapter(authoritiesConverter));
    //     return converter;
    // }

}

