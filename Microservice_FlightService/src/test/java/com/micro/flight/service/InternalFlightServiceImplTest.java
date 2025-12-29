package com.micro.flight.service;

import static org.mockito.Mockito.when;

import java.time.LocalDateTime;

import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.junit.jupiter.api.extension.ExtendWith;

import com.micro.flight.entity.Flight;
import com.micro.flight.exception.ResourceNotFoundException;
import com.micro.flight.repository.FlightRepository;

import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

@ExtendWith(MockitoExtension.class)
class InternalFlightServiceImplTest {

    @Mock
    private FlightRepository flightRepository;

    @InjectMocks
    private InternalFlightServiceImpl service;

    @Test
    void getFlightById_success() {
        Flight flight = new Flight();
        flight.setId("F1");
        flight.setAvailableSeats(10);
        flight.setDeparture(LocalDateTime.now());

        when(flightRepository.findById("F1"))
                .thenReturn(Mono.just(flight));

        StepVerifier.create(service.getFlightById("F1"))
                .expectNextMatches(dto -> dto.getAvailableSeats() == 10)
                .verifyComplete();
    }

    @Test
    void getFlightById_notFound() {
        when(flightRepository.findById("X"))
                .thenReturn(Mono.empty());

        StepVerifier.create(service.getFlightById("X"))
                .expectError(ResourceNotFoundException.class)
                .verify();
    }

    @Test
    void updateAvailableSeats_success() {
        Flight flight = new Flight();
        flight.setId("F1");

        when(flightRepository.findById("F1"))
                .thenReturn(Mono.just(flight));
        when(flightRepository.save(flight))
                .thenReturn(Mono.just(flight));

        StepVerifier.create(service.updateAvailableSeats("F1", 20))
                .verifyComplete();
    }
}
