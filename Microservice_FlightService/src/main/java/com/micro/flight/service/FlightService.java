package com.micro.flight.service;

import org.springframework.stereotype.Service;

import com.micro.flight.entity.Flight;
import com.micro.flight.requests.SearchRequests;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Service
public interface FlightService {
	Mono<Flight> addFlight(Flight flight);
    Flux<Flight> searchFlights(SearchRequests searchRequest);
    Mono<Flight> getFlightById(String id);
    Flux<Flight> getAllFlights();
}