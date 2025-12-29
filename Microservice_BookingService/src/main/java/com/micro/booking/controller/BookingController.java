package com.micro.booking.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.micro.booking.entity.Ticket;
import com.micro.booking.exception.ResourceNotFoundException;
import com.micro.booking.exception.UnprocessableException;
import com.micro.booking.requests.BookingRequest;
import com.micro.booking.service.BookingService;

import jakarta.validation.Valid;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api/flight")
// @CrossOrigin(origins = "http://localhost:4200")
public class BookingController {

    @Autowired
    private BookingService bookingService;

    @PostMapping("/booking/{flightId}")
    public Mono<ResponseEntity<Object>> bookFlight(
            @PathVariable String flightId,
            @Valid @RequestBody BookingRequest bookingRequest) {
        return bookingService.bookFlight(flightId, bookingRequest)
                .map(ticket -> ResponseEntity.status(HttpStatus.CREATED).body((Object) ticket))
                .onErrorResume(ResourceNotFoundException.class, 
                        e -> Mono.just(ResponseEntity.status(HttpStatus.NOT_FOUND).body(e.getMessage())))
                .onErrorResume(UnprocessableException.class, 
                        e -> Mono.just(ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body(e.getMessage())))
                .onErrorResume(RuntimeException.class, 
                	    e -> Mono.just(ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(e.getMessage())))
                .onErrorResume(Exception.class, 
                    e -> Mono.just(ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An error occurred: " + e.getMessage())));
    }

    @GetMapping("/ticket/{pnr}")
    public Mono<ResponseEntity<Object>> getTicket(@PathVariable String pnr) {
        return bookingService.getTicketByPnr(pnr)
                .map(ticket -> ResponseEntity.ok((Object) ticket))
                .onErrorResume(ResourceNotFoundException.class, 
                    e -> Mono.just(ResponseEntity.status(HttpStatus.NOT_FOUND).body(e.getMessage())));
    }

    @GetMapping("/booking/history/{emailId}")
    public Mono<ResponseEntity<Object>> getBookingHistory(@PathVariable String emailId) {
        return bookingService.getBookingHistory(emailId)
            .collectList() 
            .flatMap(tickets -> {
                if (tickets.isEmpty()) {
                    return Mono.just(ResponseEntity.status(HttpStatus.NOT_FOUND)
                            .body("No booking history found for email: " + emailId));
                } else {
                    return Mono.just(ResponseEntity.ok((Object) tickets));
                }
            });
    }

    @DeleteMapping("/booking/cancel/{pnr}")
    public Mono<ResponseEntity<String>> cancelTicket(@PathVariable String pnr) {
        return bookingService.cancelTicket(pnr)
                .map(ResponseEntity::ok)
                .onErrorResume(ResourceNotFoundException.class, 
                    e -> Mono.just(ResponseEntity.status(HttpStatus.NOT_FOUND).body(e.getMessage())))
                .onErrorResume(UnprocessableException.class, 
                    e -> Mono.just(ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body(e.getMessage())));
    }
}
