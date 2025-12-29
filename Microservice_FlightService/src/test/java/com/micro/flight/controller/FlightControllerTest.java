package com.micro.flight.controller;

import static org.mockito.Mockito.when;

import java.time.LocalDate;
import java.time.LocalDateTime;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;

import com.micro.flight.entity.Flight;
import com.micro.flight.requests.SearchRequests;
import com.micro.flight.requests.Trip;
import com.micro.flight.service.FlightService;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@WebFluxTest(controllers = FlightController.class)
class FlightControllerTest {

    @Autowired
    private WebTestClient webTestClient;

    @MockBean
    private FlightService flightService;
    
    @Test
    void addFlight_success() {

        String validFlightJson = """
        {
          "airline_name": "INDIGO",
          "airline_logo": "https://indigo.png",
          "flightNumber": "6E123",
          "fromPlace": "Mumbai",
          "toPlace": "Delhi",
          "departure": "2026-02-20T10:00:00",
          "arrival": "2026-02-20T12:30:00",
          "price": 5500,
          "availableSeats": 120,
          "mealType": "BOTH"
        }
        """;

        Flight savedFlight = new Flight();
        savedFlight.setId("F1");

        Mockito.when(flightService.addFlight(Mockito.any()))
                .thenReturn(Mono.just(savedFlight));

        webTestClient.post()
                .uri("/api/flight/airline/inventory")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(validFlightJson)
                .exchange()
                .expectStatus().isCreated()
                .expectBody()
                .jsonPath("$.id").isEqualTo("F1");
    }
    
    @Test
    void addFlight_validationFailure() {

        String invalidJson = "{}";

        webTestClient.post()
                .uri("/api/flight/airline/inventory")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(invalidJson)
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.error").isEqualTo("Validation Failed");
    }

    @Test
    void searchFlights_success() {
        SearchRequests request = new SearchRequests(
                "DEL", "BOM",
                LocalDate.now().plusDays(1),
                null,
                Trip.ONE_WAY
        );

        when(flightService.searchFlights(Mockito.any()))
                .thenReturn(Flux.just(new Flight()));

        webTestClient.post()
                .uri("/api/flight/search")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(request)
                .exchange()
                .expectStatus().isOk()
                .expectBodyList(Flight.class)
                .hasSize(1);
    }

    @Test
    void searchFlights_validationError() {
        SearchRequests invalid = new SearchRequests();

        webTestClient.post()
                .uri("/api/flight/search")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(invalid)
                .exchange()
                .expectStatus().isBadRequest();
    }

    @Test
    void getAllFlights_success() {
        when(flightService.getAllFlights())
                .thenReturn(Flux.just(new Flight(), new Flight()));

        webTestClient.get()
                .uri("/api/flight/airline/inventory/all")
                .exchange()
                .expectStatus().isOk()
                .expectBodyList(Flight.class)
                .hasSize(2);
    }
}
