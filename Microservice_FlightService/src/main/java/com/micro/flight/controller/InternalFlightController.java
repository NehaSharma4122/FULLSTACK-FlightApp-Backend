package com.micro.flight.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.micro.flight.requests.InternalFlightRequest;
import com.micro.flight.service.InternalFlightService;

import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/flights")
public class InternalFlightController {

    @Autowired
    private InternalFlightService internalFlightService;

    @GetMapping("/{flightId}")
    public Mono<ResponseEntity<InternalFlightRequest>> getFlightById(
            @PathVariable("flightId") String flightId) {

        return internalFlightService.getFlightById(flightId)
                .map(ResponseEntity::ok);
    }

    @PutMapping("/{flightId}/seats/{seats}")
    public Mono<ResponseEntity<Void>> updateAvailableSeats(
            @PathVariable("flightId") String flightId,
            @PathVariable int seats) {

        return internalFlightService.updateAvailableSeats(flightId, seats)
                .then(Mono.just(ResponseEntity.noContent().build()));
    }
}
