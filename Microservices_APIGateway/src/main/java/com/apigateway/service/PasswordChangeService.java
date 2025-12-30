package com.apigateway.service;

import com.apigateway.entity.User;
import com.apigateway.repository.UserRepository;
import com.apigateway.request.ChangePasswordRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;

@Service
@RequiredArgsConstructor
public class PasswordChangeService {

    private final UserRepository userRepository;
    private final PasswordEncoder encoder;
    private final PasswordPolicyService policy;

    public Mono<User> changePassword(User user, ChangePasswordRequest req) {
    try {
            System.out.println("===== CHANGE PASSWORD DEBUG =====");
            System.out.println("User = " + user.getEmail());
            System.out.println("OldPwd match = "
                    + encoder.matches(req.getOldPassword(), user.getPassword()));
            System.out.println("PwdHistory size = "
                    + (user.getPasswordHistory() == null ? "null"
                                                        : user.getPasswordHistory().size()));
            System.out.println("LastPwdChange = " + user.getLastPasswordChangedAt());
        }
        catch (Exception e) {
            e.printStackTrace();
        }

        if (!encoder.matches(req.getOldPassword(), user.getPassword())) {
            return Mono.error(new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED,
                    "Old password is incorrect"
            ));
        }

        policy.validatePasswordStrength(req.getNewPassword());
        policy.validatePasswordHistory(user, req.getNewPassword());

        String newHash = encoder.encode(req.getNewPassword());

        policy.updatePasswordHistory(user, newHash);

        user.setPassword(newHash);

        return userRepository.save(user);
    }
}
