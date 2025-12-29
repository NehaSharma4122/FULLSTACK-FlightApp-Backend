package com.micro.flight.service;

import static org.hamcrest.CoreMatchers.any;
import static org.mockito.Mockito.when;

import java.time.LocalDate;
import java.time.LocalDateTime;

import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.junit.jupiter.api.extension.ExtendWith;

import com.micro.flight.entity.Flight;
import com.micro.flight.exception.ResourceNotFoundException;
import com.micro.flight.exception.UnprocessableException;
import com.micro.flight.repository.FlightRepository;
import com.micro.flight.requests.SearchRequests;
import com.micro.flight.requests.Trip;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;


@ExtendWith(MockitoExtension.class)
class FlightServiceImplTest {

    @Mock
    private FlightRepository flightRepository;

    @InjectMocks
    private FlightServiceImpl flightService;

    @Test
    void searchFlights_oneWay() {
        SearchRequests req = new SearchRequests(
                "DEL", "BOM",
                LocalDate.now().plusDays(1),
                null,
                Trip.ONE_WAY
        );

        when(flightRepository.findByFromPlaceAndToPlaceAndDepartureBetween(
                Mockito.any(), Mockito.any(),
                Mockito.any(), Mockito.any()))
                .thenReturn(Flux.just(new Flight()));

        StepVerifier.create(flightService.searchFlights(req))
                .expectNextCount(1)
                .verifyComplete();
    }

    @Test
    void searchFlights_roundTrip_success() {
        SearchRequests req = new SearchRequests(
                "DEL", "BOM",
                LocalDate.now().plusDays(1),
                LocalDate.now().plusDays(2),
                Trip.ROUND_TRIP
        );

        when(flightRepository.findByFromPlaceAndToPlaceAndDepartureBetween(
                Mockito.any(), Mockito.any(),
                Mockito.any(), Mockito.any()))
                .thenReturn(Flux.just(new Flight()));

        StepVerifier.create(flightService.searchFlights(req))
                .expectNextCount(2)
                .verifyComplete();
    }

    @Test
    void searchFlights_roundTrip_missingReturnDate() {
        SearchRequests req = new SearchRequests(
                "DEL", "BOM",
                LocalDate.now().plusDays(1),
                null,
                Trip.ROUND_TRIP
        );

        StepVerifier.create(flightService.searchFlights(req))
                .expectError(UnprocessableException.class)
                .verify();
    }

    @Test
    void searchFlights_roundTrip_invalidReturnDate() {
        SearchRequests req = new SearchRequests(
                "DEL", "BOM",
                LocalDate.now().plusDays(2),
                LocalDate.now().plusDays(1),
                Trip.ROUND_TRIP
        );

        StepVerifier.create(flightService.searchFlights(req))
                .expectError(UnprocessableException.class)
                .verify();
    }

    @Test
    void getFlightById_notFound() {
        when(flightRepository.findById("X"))
                .thenReturn(Mono.empty());

        StepVerifier.create(flightService.getFlightById("X"))
                .expectError(ResourceNotFoundException.class)
                .verify();
    }

    @Test
    void getAllFlights() {
        when(flightRepository.findAll())
                .thenReturn(Flux.just(new Flight()));

        StepVerifier.create(flightService.getAllFlights())
                .expectNextCount(1)
                .verifyComplete();
    }
    
    @Test
    void searchFlights_unknownTripType_fallbackPath() {

        SearchRequests request = new SearchRequests();
        request.setFromPlace("DEL");
        request.setToPlace("BOM");
        request.setTravelDate(LocalDate.now().plusDays(1));
        request.setTripType(null); // forces fallback

        when(flightRepository.findByFromPlaceAndToPlaceAndDepartureBetween(
                any(), any(), any(), any()))
                .thenReturn(Flux.empty());

        StepVerifier.create(flightService.searchFlights(request))
                .verifyComplete();
    }

}
