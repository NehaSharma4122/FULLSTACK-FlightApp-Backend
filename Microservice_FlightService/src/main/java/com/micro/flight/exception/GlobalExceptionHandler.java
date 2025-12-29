package com.micro.flight.exception;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.bind.support.WebExchangeBindException;

import com.micro.flight.exception.ForbiddenException;
import com.micro.flight.exception.ResourceConflictException;
import com.micro.flight.exception.ResourceNotFoundException;
import com.micro.flight.exception.UnauthorizedException;
import com.micro.flight.exception.UnprocessableException;

import reactor.core.publisher.Mono;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private Mono<ResponseEntity<Map<String, Object>>> buildResponse(
            HttpStatus status, String message, String exceptionType) {

        Map<String, Object> body = new HashMap<>();
        body.put("timestamp", LocalDateTime.now());
        body.put("status", status.value());
        body.put("error", status.getReasonPhrase());
        body.put("message", message);
        body.put("exceptionType", exceptionType);

        return Mono.just(ResponseEntity.status(status).body(body));
    }


    @ExceptionHandler(ResourceNotFoundException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleNotFound(ResourceNotFoundException ex) {
        return buildResponse(HttpStatus.NOT_FOUND, ex.getMessage(), ex.getClass().getSimpleName());
    }


    @ExceptionHandler(ResourceConflictException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleConflict(ResourceConflictException ex) {
        return buildResponse(HttpStatus.CONFLICT, ex.getMessage(), ex.getClass().getSimpleName());
    }



    @ExceptionHandler(UnprocessableException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleUnprocessable(UnprocessableException ex) {
        return buildResponse(HttpStatus.UNPROCESSABLE_ENTITY, ex.getMessage(), ex.getClass().getSimpleName());
    }


    @ExceptionHandler(RuntimeException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleRuntime(RuntimeException ex) {
        return buildResponse(HttpStatus.BAD_REQUEST, ex.getMessage(), ex.getClass().getSimpleName());
    }


    @ExceptionHandler(UnauthorizedException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleUnauthorized(UnauthorizedException ex) {
        return buildResponse(HttpStatus.UNAUTHORIZED, ex.getMessage(), ex.getClass().getSimpleName());
    }

    @ExceptionHandler(ForbiddenException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleForbidden(ForbiddenException ex) {
        return buildResponse(HttpStatus.FORBIDDEN, ex.getMessage(), ex.getClass().getSimpleName());
    }


    @ExceptionHandler(MethodArgumentNotValidException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleValidation(MethodArgumentNotValidException ex) {

        Map<String, Object> body = new HashMap<>();
        body.put("timestamp", LocalDateTime.now());
        body.put("status", HttpStatus.BAD_REQUEST.value());
        body.put("error", "Validation Failed");
        Map<String, String> errors = new HashMap<>();

        ex.getBindingResult().getFieldErrors().forEach(err ->
                errors.put(err.getField(), err.getDefaultMessage())
        );

        body.put("validationErrors", errors);
        body.put("message", "Input validation failed");

        return Mono.just(ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body));
    }


    @ExceptionHandler(Exception.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleGeneric(Exception ex) {
        ex.printStackTrace(); // optional logging
        return buildResponse(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage(), ex.getClass().getSimpleName());
    }
    
    @ExceptionHandler(WebExchangeBindException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleWebFluxValidation(
            WebExchangeBindException ex) {

        Map<String, Object> body = new HashMap<>();
        body.put("timestamp", LocalDateTime.now());
        body.put("status", HttpStatus.BAD_REQUEST.value());
        body.put("error", "Validation Failed");

        Map<String, String> errors = new HashMap<>();

        ex.getFieldErrors().forEach(err ->
                errors.put(err.getField(), err.getDefaultMessage())
        );

        body.put("validationErrors", errors);
        body.put("message", "Input validation failed");

        return Mono.just(ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body));
    }

}
