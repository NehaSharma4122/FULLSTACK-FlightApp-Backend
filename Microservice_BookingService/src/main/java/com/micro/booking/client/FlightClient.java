package com.micro.booking.client;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.micro.booking.requests.FlightRequest;

import reactor.core.publisher.Mono;

@FeignClient(name = "MICROSERVICE-FLIGHTSERVICE",
url = "${flight.service.url}",
fallbackFactory = FlightFallbackFactory.class)
public interface FlightClient {

    @GetMapping("/flights/{flightId}")
    FlightRequest getFlightById(@PathVariable("flightId") String flightId);

    @PutMapping("/flights/{flightId}/seats/{seats}")
    void updateAvailableSeats(
            @PathVariable("flightId") String flightId,
            @PathVariable("seats") int seats
    );
}
