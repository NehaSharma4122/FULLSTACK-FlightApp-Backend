package com.micro.booking.client;

import com.micro.booking.exception.ResourceNotFoundException;
import com.micro.booking.exception.ServiceUnavailableException;
import com.micro.booking.requests.FlightRequest;

import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;

import org.springframework.cloud.openfeign.FallbackFactory;
import org.springframework.stereotype.Component;
import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class FlightFallbackFactory implements FallbackFactory<FlightClient> {

    @Override
    public FlightClient create(Throwable cause) {
        return new FlightClient() {
            @Override
            public FlightRequest getFlightById(String flightId) {
                log.error("Error calling Flight Service for ID {}: {}", flightId, cause.getMessage());
                throw new ServiceUnavailableException("Flight Service is currently unavailable. Please try again later.");
            }
            
            @Override
            public void updateAvailableSeats(String flightId, int seats) {
                log.error("Error updating seats for ID {}: {}", flightId, cause.getMessage());
                throw new ServiceUnavailableException("Unable to update seats at this time.");
            }
        };
    }
}