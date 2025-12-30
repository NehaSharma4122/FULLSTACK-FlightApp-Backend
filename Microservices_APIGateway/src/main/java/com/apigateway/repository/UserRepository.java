package com.apigateway.repository;

import org.springframework.data.mongodb.repository.ReactiveMongoRepository;
import com.apigateway.entity.User;
import reactor.core.publisher.Mono;

public interface UserRepository extends ReactiveMongoRepository<User, String> {
	Mono<Boolean> existsByUsername(String username);
    Mono<Boolean> existsByEmail(String email);
    Mono<User> findByEmail(String email);
    Mono<User> findByUsername(String username);
}
