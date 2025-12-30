package com.apigateway.controller;

import com.apigateway.entity.BlacklistedToken;
import com.apigateway.entity.Role;
import com.apigateway.entity.User;
import com.apigateway.jwt.JWTUtils;
import com.apigateway.repository.BlacklistedTokenRepository;
import com.apigateway.repository.UserRepository;
import com.apigateway.request.ChangePasswordRequest;
import com.apigateway.request.ChangePasswordResponse;
import com.apigateway.request.JWTResponse;
import com.apigateway.request.LoginRequest;
import com.apigateway.request.SignoutResponse;
import com.apigateway.request.SignupRequest;
import com.apigateway.request.SignupResponse;
import com.apigateway.service.PasswordChangeService;
import com.apigateway.service.PasswordPolicyService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.Date;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final PasswordPolicyService passwordPolicyService;
    private final BlacklistedTokenRepository blacklistedTokenRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JWTUtils jwtUtils;
    private final PasswordChangeService passwordChangeService;


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

                    User user = new User();
                        user.setId(null);
                        user.setUsername(request.getUsername());
                        user.setEmail(request.getEmail());
                        user.setPassword(encryptedPassword);
                        user.setRole(request.getRole() != null ? request.getRole() : Role.ROLE_USER);

                        // password policy defaults
                        user.setPasswordHistory(new java.util.ArrayList<>());
                        user.setLastPasswordChangedAt(new Date());
                        user.setFailedAttempts(0);
                        user.setAccountLockedUntil(null);
                        user.setForcePasswordChange(false);

                    return userRepository.save(user)
                            .map(savedUser ->
                                    ResponseEntity.status(HttpStatus.CREATED)
                                            .body(new SignupResponse(
                                                    savedUser.getUsername(),
                                                    savedUser.getEmail(),
                                                    savedUser.getPassword(),
                                                    savedUser.getRole()
                                            ))
                            );
                });
        }

        @PostMapping("/signin")
        public Mono<ResponseEntity<JWTResponse>> login(
                @Valid @RequestBody LoginRequest request) {

        return userRepository.findByEmail(request.getEmail())
                .switchIfEmpty(Mono.error(new ResponseStatusException(
                        HttpStatus.UNAUTHORIZED,
                        "Invalid email or password"
                )))
                .flatMap(user -> {
                        
        // ===== DEBUG TRACE (temporary) =====
                        try {
                                System.out.println("===== LOGIN DEBUG TRACE =====");
                                System.out.println("User = " + user.getEmail());
                                System.out.println("Role = " + user.getRole());
                                System.out.println("LastPwdChange = " + user.getLastPasswordChangedAt());
                                System.out.println("AccountLockedUntil = " + user.getAccountLockedUntil());
                                System.out.println("FailedAttempts = " + user.getFailedAttempts());
                        }
                        catch (Exception e) {
                                e.printStackTrace();
                        }
                        if (user.getPasswordHistory() == null)
                                user.setPasswordHistory(new ArrayList<>());

                        if (user.getLastPasswordChangedAt() == null)
                                user.setLastPasswordChangedAt(new Date());

                        if (user.getAccountLockedUntil() == null)
                                user.setAccountLockedUntil(null);

                        if (user.getRole() == null)
                                user.setRole(Role.ROLE_USER);

                        // ===== Account Lock Check =====
                        if (passwordPolicyService.isAccountLocked(user)) {
                        return Mono.error(new ResponseStatusException(
                                HttpStatus.LOCKED,
                                "Account locked. Try again later."
                        ));
                        }

                        // ===== Validate Password =====
                        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {

                                passwordPolicyService.applyLockoutPolicy(user);

                                return userRepository.save(user)
                                        .then(Mono.error(new ResponseStatusException(
                                                HttpStatus.UNAUTHORIZED,
                                                "Invalid email or password"
                                        )));
                        }

                        // Reset failed attempts on success
                        passwordPolicyService.clearLockoutState(user);

                        // ===== Require Password Reset =====
                        if (user.isForcePasswordChange()
                                || passwordPolicyService.isPasswordExpired(user)) {

                                return userRepository.save(user)
                                        .then(Mono.error(new ResponseStatusException(
                                                HttpStatus.UPGRADE_REQUIRED,
                                                "Password expired. Please change your password."
                                        )));
                        }

                        return userRepository.save(user)
                                .map(saved -> {

                                Role role = saved.getRole() != null ?
                                        saved.getRole() : Role.ROLE_USER;

                                String token = jwtUtils.generateToken(
                                        saved.getEmail(),
                                        saved.getUsername(),
                                        role
                                );

                                return ResponseEntity.ok(
                                        new JWTResponse(
                                                saved.getUsername(),
                                                saved.getEmail(),
                                                role,
                                                token
                                        )
                                );
                                });
                                
                                
                })
                .onErrorResume(ex -> {
                                ex.printStackTrace();
                                return Mono.error(new ResponseStatusException(
                                        HttpStatus.INTERNAL_SERVER_ERROR,
                                        "AUTH ERROR: " + ex.getClass().getSimpleName() + " - " + ex.getMessage()
                        ));
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

        @PostMapping("/change-password")
        public Mono<ResponseEntity<ChangePasswordResponse>> changePassword(
                @RequestHeader("Authorization") String authHeader,
                @RequestBody ChangePasswordRequest request
        ) {
        if (!authHeader.startsWith("Bearer "))
                return Mono.error(new ResponseStatusException(
                        HttpStatus.BAD_REQUEST,
                        "Invalid Authorization header"
                ));

        String token = authHeader.substring(7);
        String email = jwtUtils.getSubject(token);

        return userRepository.findByEmail(email)
                .switchIfEmpty(Mono.error(new ResponseStatusException(
                        HttpStatus.NOT_FOUND,
                        "User not found"
                )))
                .flatMap(user -> {

                // ---- DEFAULTS FOR OLD USERS ----
                if (user.getPasswordHistory() == null)
                    user.setPasswordHistory(new ArrayList<>());

                if (user.getLastPasswordChangedAt() == null)
                    user.setLastPasswordChangedAt(new Date());

                if (user.getFailedAttempts() == null)
                    user.setFailedAttempts(0);

                if (user.getAccountLockedUntil() == null)
                    user.setAccountLockedUntil(null);
                // ---------------------------------

                return passwordChangeService.changePassword(user, request);
            })
            .map(u -> ResponseEntity.ok(
                    new ChangePasswordResponse("Password updated successfully")
            ));
        }
}
