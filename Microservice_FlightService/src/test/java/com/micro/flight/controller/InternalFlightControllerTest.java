package com.micro.flight.controller;

import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.web.reactive.server.WebTestClient;

import com.micro.flight.requests.InternalFlightRequest;
import com.micro.flight.service.InternalFlightService;

import reactor.core.publisher.Mono;

@WebFluxTest(controllers = InternalFlightController.class)
class InternalFlightControllerTest {

    @Autowired
    private WebTestClient webTestClient;

    @MockBean
    private InternalFlightService internalFlightService;

    @Test
    void getFlightById_success() {
        InternalFlightRequest dto = new InternalFlightRequest();
        dto.setId("F1");

        when(internalFlightService.getFlightById("F1"))
                .thenReturn(Mono.just(dto));

        webTestClient.get()
                .uri("/flights/F1")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.id").isEqualTo("F1");
    }

    @Test
    void updateAvailableSeats_success() {
        when(internalFlightService.updateAvailableSeats("F1", 10))
                .thenReturn(Mono.empty());

        webTestClient.put()
                .uri("/flights/F1/seats/10")
                .exchange()
                .expectStatus().isNoContent();
    }
}
