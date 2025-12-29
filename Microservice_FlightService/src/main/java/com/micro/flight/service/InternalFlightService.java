package com.micro.flight.service;

import com.micro.flight.requests.InternalFlightRequest;

import reactor.core.publisher.Mono;

public interface InternalFlightService {
	Mono<InternalFlightRequest> getFlightById(String flightId);
    Mono<Void> updateAvailableSeats(String flightId, int seats);
}
