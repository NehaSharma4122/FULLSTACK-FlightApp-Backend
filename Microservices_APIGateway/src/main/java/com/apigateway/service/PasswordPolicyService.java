package com.apigateway.service;

import com.apigateway.entity.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Date;
import java.util.List;

@Slf4j
@Service
public class PasswordPolicyService {

    // ===== Organization Security Policy =====

    private static final int MIN_LENGTH = 8;
    private static final int PASSWORD_HISTORY_LIMIT = 5;
    private static final int EXPIRY_DAYS = 60;

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final int LOCK_MINUTES = 15;

    private final PasswordEncoder encoder;

    public PasswordPolicyService(PasswordEncoder encoder) {
        this.encoder = encoder;
    }

    public boolean isPasswordExpired(User user) {
        if (user.getLastPasswordChangedAt() == null) return true;

        long ageDays =
                Duration.between(
                        user.getLastPasswordChangedAt().toInstant(),
                        new Date().toInstant()
                ).toDays();

        return ageDays >= EXPIRY_DAYS;
    }

    public boolean isAccountLocked(User user) {
            if (user.getAccountLockedUntil() == null) return false;
            return user.getAccountLockedUntil().after(new Date());
    }

    public void applyLockoutPolicy(User user) {
        user.setFailedAttempts(user.getFailedAttempts() + 1);

        if (user.getFailedAttempts() >= MAX_FAILED_ATTEMPTS) {
            Date unlock = new Date(System.currentTimeMillis() + (LOCK_MINUTES * 60 * 1000));
            user.setAccountLockedUntil(unlock);
            user.setFailedAttempts(0);

            log.warn("User {} locked until {}", user.getEmail(), unlock);
        }
    }

    public void clearLockoutState(User user) {
        user.setFailedAttempts(0);
        user.setAccountLockedUntil(null);
    }


    public void validatePasswordStrength(String password) {

        if (password.length() < MIN_LENGTH)
            throw new IllegalArgumentException(
                    "Password must be at least " + MIN_LENGTH + " characters (15+ recommended)"
            );

        if (!password.matches(".*[A-Z].*"))
            throw new IllegalArgumentException("Password must contain an uppercase letter");

        if (!password.matches(".*[a-z].*"))
            throw new IllegalArgumentException("Password must contain a lowercase letter");

        if (!password.matches(".*[0-9].*"))
            throw new IllegalArgumentException("Password must contain a number");

        if (!password.matches(".*[!@#$%^&*()\\-_=+{};:,<.>/?].*"))
            throw new IllegalArgumentException("Password must contain a special character");
    }

    public void validatePasswordHistory(User user, String newPassword) {

        if (user.getPasswordHistory() == null) return;

        for (String oldHash : user.getPasswordHistory()) {
            if (encoder.matches(newPassword, oldHash)) {
                throw new IllegalArgumentException(
                        "You cannot reuse your previous " + PASSWORD_HISTORY_LIMIT + " passwords"
                );
            }
        }
    }

    public void updatePasswordHistory(User user, String newHash) {

        List<String> history = user.getPasswordHistory();

        if (history == null) {
            history = new java.util.ArrayList<>();
        }

        history.add(0, newHash);

        if (history.size() > PASSWORD_HISTORY_LIMIT)
            history = history.subList(0, PASSWORD_HISTORY_LIMIT);

        user.setPasswordHistory(history);
        user.setLastPasswordChangedAt(new Date());
        user.setForcePasswordChange(false);
    }
}
