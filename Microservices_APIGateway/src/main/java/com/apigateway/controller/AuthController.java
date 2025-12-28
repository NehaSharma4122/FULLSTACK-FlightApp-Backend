package com.apigateway.controller;

import com.apigateway.entity.BlacklistedToken;
import com.apigateway.entity.Role;
import com.apigateway.entity.User;
import com.apigateway.jwt.JWTUtils;
import com.apigateway.repository.BlacklistedTokenRepository;
import com.apigateway.repository.UserRepository;
import com.apigateway.request.JWTResponse;
import com.apigateway.request.LoginRequest;
import com.apigateway.request.SignoutResponse;
import com.apigateway.request.SignupRequest;
import com.apigateway.request.SignupResponse;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import reactor.core.publisher.Mono;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
	private final BlacklistedTokenRepository blacklistedTokenRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JWTUtils jwtUtils;

    @PostMapping("/signup")
    public Mono<ResponseEntity<SignupResponse>> register(
            @Valid @RequestBody SignupRequest request) {

        return userRepository.existsByUsername(request.getUsername())
                .flatMap(usernameExists -> {
                    if (usernameExists) {
                        return Mono.error(new ResponseStatusException(
                                HttpStatus.CONFLICT, "Username already exists"));
                    }
                    return userRepository.existsByEmail(request.getEmail());
                })
                .flatMap(emailExists -> {
                    if (emailExists) {
                        return Mono.error(new ResponseStatusException(
                                HttpStatus.CONFLICT, "Email already exists"));
                    }

                    String encryptedPassword =
                            passwordEncoder.encode(request.getPassword());

                    User user = new User(
                            null,
                            request.getUsername(),
                            request.getEmail(),
                            encryptedPassword,
                            request.getRole() != null ? request.getRole() : Role.ROLE_USER
                    );

                    return userRepository.save(user)
                            .map(savedUser ->
                                    ResponseEntity.status(HttpStatus.CREATED)
                                            .body(new SignupResponse(
                                                    savedUser.getUsername(),
                                                    savedUser.getEmail(),
                                                    savedUser.getPassword()
                                            ))
                            );
                });
        }

        @PostMapping("/signin")
        public Mono<ResponseEntity<JWTResponse>> login(
                @Valid @RequestBody LoginRequest request) {

        return userRepository.findByEmail(request.getEmail())
                .switchIfEmpty(Mono.error(
                        new ResponseStatusException(
                                HttpStatus.UNAUTHORIZED,
                                "Invalid email or password"
                        )
                ))
                .filter(user ->
                        passwordEncoder.matches(
                                request.getPassword(),
                                user.getPassword()))
                .switchIfEmpty(Mono.error(
                        new ResponseStatusException(
                                HttpStatus.UNAUTHORIZED,
                                "Invalid email or password"
                        )
                ))
                .map(user -> {
                        Role role = user.getRole() != null
                                ? user.getRole()
                                : Role.ROLE_USER;  
                        String token = jwtUtils.generateToken(
                        user.getEmail(),
                        user.getUsername(),
                        role
                );

                return ResponseEntity.ok(
                        new JWTResponse(
                                user.getUsername(),
                                user.getEmail(),
                                role,
                                token
                        )
                );
                });
        }

    @PostMapping("/signout")
    public Mono<ResponseEntity<SignoutResponse>> logout(
            @RequestHeader("Authorization") String authHeader) {

        if (!authHeader.startsWith("Bearer ")) {
            return Mono.error(new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Invalid Authorization header"
            ));
        }

        String token = authHeader.substring(7);

        if (!jwtUtils.validate(token)) {
            return Mono.error(new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED,
                    "Invalid or expired token"
            ));
        }

        String email = jwtUtils.getSubject(token);

        return blacklistedTokenRepository.existsByToken(token)
                .flatMap(alreadyBlacklisted -> {

                    if (alreadyBlacklisted) {
                        return Mono.error(new ResponseStatusException(
                                HttpStatus.CONFLICT,
                                "Token already logged out"
                        ));
                    }

                    BlacklistedToken blacklistedToken = new BlacklistedToken(
                            null,
                            token,
                            jwtUtils.getExpiry(token)
                    );

                    return blacklistedTokenRepository.save(blacklistedToken)
                            .map(saved ->
                                    ResponseEntity.ok(
                                            new SignoutResponse(
                                                    email,
                                                    "Logged out successfully"
                                            )
                                    )
                            );
                });
    }
}
