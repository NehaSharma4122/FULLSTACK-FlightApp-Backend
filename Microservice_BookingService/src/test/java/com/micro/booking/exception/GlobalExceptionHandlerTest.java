package com.micro.booking.exception;

import static org.junit.jupiter.api.Assertions.*;

import java.time.LocalDateTime;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.support.WebExchangeBindException;
import org.springframework.validation.FieldError;
import org.springframework.core.MethodParameter;

import reactor.core.publisher.Mono;

class GlobalExceptionHandlerTest {

    private final GlobalExceptionHandler handler = new GlobalExceptionHandler();

    /* ---------------- NOT FOUND ---------------- */

    @Test
    void testHandleNotFound() {
        ResourceNotFoundException ex =
                new ResourceNotFoundException("Flight not found");

        ResponseEntity<Map<String, Object>> response =
                handler.handleNotFound(ex).block();

        assertNotNull(response);
        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        assertEquals("Flight not found", response.getBody().get("message"));
        assertEquals("ResourceNotFoundException", response.getBody().get("exceptionType"));
    }

    /* ---------------- CONFLICT ---------------- */

    @Test
    void testHandleConflict() {
        ResourceConflictException ex =
                new ResourceConflictException("Conflict occurred");

        ResponseEntity<Map<String, Object>> response =
                handler.handleConflict(ex).block();

        assertEquals(HttpStatus.CONFLICT, response.getStatusCode());
        assertEquals("Conflict occurred", response.getBody().get("message"));
    }

    /* ---------------- UNPROCESSABLE ---------------- */

    @Test
    void testHandleUnprocessable() {
        UnprocessableException ex =
                new UnprocessableException("Invalid input");

        ResponseEntity<Map<String, Object>> response =
                handler.handleUnprocessable(ex).block();

        assertEquals(HttpStatus.UNPROCESSABLE_ENTITY, response.getStatusCode());
        assertEquals("Invalid input", response.getBody().get("message"));
    }

    /* ---------------- UNAUTHORIZED ---------------- */

    @Test
    void testHandleUnauthorized() {
        UnauthorizedException ex =
                new UnauthorizedException("Unauthorized");

        ResponseEntity<Map<String, Object>> response =
                handler.handleUnauthorized(ex).block();

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertEquals("Unauthorized", response.getBody().get("message"));
    }

    /* ---------------- FORBIDDEN ---------------- */

    @Test
    void testHandleForbidden() {
        ForbiddenException ex =
                new ForbiddenException("Access denied");

        ResponseEntity<Map<String, Object>> response =
                handler.handleForbidden(ex).block();

        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
        assertEquals("Access denied", response.getBody().get("message"));
    }

    /* ---------------- RUNTIME ---------------- */

    @Test
    void testHandleRuntimeException() {
        RuntimeException ex = new RuntimeException("Runtime error");

        ResponseEntity<Map<String, Object>> response =
                handler.handleRuntime(ex).block();

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals("Runtime error", response.getBody().get("message"));
        assertEquals("RuntimeException", response.getBody().get("exceptionType"));
    }

    /* ---------------- GENERIC ---------------- */

    @Test
    void testHandleGenericException() {
        Exception ex = new Exception("Something broke");

        ResponseEntity<Map<String, Object>> response =
                handler.handleGeneric(ex).block();

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals("Something broke", response.getBody().get("message"));
        assertEquals("Exception", response.getBody().get("exceptionType"));
    }

    /* ---------------- MethodArgumentNotValidException ---------------- */

    @Test
    void testHandleMethodArgumentNotValidException() {

        Object target = new Object();
        BindingResult bindingResult =
                new BeanPropertyBindingResult(target, "target");

        bindingResult.addError(
                new FieldError("target", "fromPlace", "From place is required"));
        bindingResult.addError(
                new FieldError("target", "toPlace", "To place is required"));

        MethodArgumentNotValidException ex =
                new MethodArgumentNotValidException((MethodParameter) null, bindingResult);

        ResponseEntity<Map<String, Object>> response =
                handler.handleValidation(ex).block();

        assertNotNull(response);
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());

        Map<String, Object> body = response.getBody();
        assertEquals("Validation Failed", body.get("error"));
        assertEquals("Input validation failed", body.get("message"));

        Map<String, String> errors =
                (Map<String, String>) body.get("validationErrors");

        assertEquals("From place is required", errors.get("fromPlace"));
        assertEquals("To place is required", errors.get("toPlace"));
        assertNotNull(body.get("timestamp"));
    }

    /* ---------------- WebExchangeBindException ---------------- */

    @Test
    void testHandleWebExchangeBindException() {

        BindingResult bindingResult =
                new BeanPropertyBindingResult(new Object(), "request");

        bindingResult.addError(
                new FieldError("request", "travelDate", "Travel date is required"));

        WebExchangeBindException ex =
                new WebExchangeBindException(null, bindingResult);

        ResponseEntity<Map<String, Object>> response =
                handler.handleWebFluxValidation(ex).block();

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());

        Map<String, Object> body = response.getBody();
        assertEquals("Validation Failed", body.get("error"));
        assertEquals("Input validation failed", body.get("message"));

        Map<String, String> errors =
                (Map<String, String>) body.get("validationErrors");

        assertEquals("Travel date is required", errors.get("travelDate"));
        assertNotNull(body.get("timestamp"));
    }
}
