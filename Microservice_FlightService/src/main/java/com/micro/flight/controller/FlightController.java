package com.micro.flight.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.micro.flight.entity.Flight;
import com.micro.flight.requests.SearchRequests;
import com.micro.flight.service.FlightService;

import jakarta.validation.Valid;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import org.springframework.http.HttpStatus;


@RestController
@RequestMapping("/api/flight")
public class FlightController {

    @Autowired
    private FlightService flightService;

    @PostMapping("/airline/inventory")
    public Mono<ResponseEntity<Flight>> addFlight(@Valid @RequestBody Flight flight) {
        return flightService.addFlight(flight)
                .map(savedFlight ->ResponseEntity.status(HttpStatus.CREATED).body(savedFlight));
    }

    @PostMapping("/search")
    public Flux<Flight> searchFlights(@Valid @RequestBody SearchRequests searchRequest) {
        return flightService.searchFlights(searchRequest);
    }

    @GetMapping("/airline/inventory/all")
    public Flux<Flight> getAllFlights() {
        return flightService.getAllFlights();
    }
}