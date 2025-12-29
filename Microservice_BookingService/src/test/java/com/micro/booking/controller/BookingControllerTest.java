package com.micro.booking.controller;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;

import com.micro.booking.entity.Passenger;
import com.micro.booking.entity.Ticket;
import com.micro.booking.exception.ResourceNotFoundException;
import com.micro.booking.exception.UnprocessableException;
import com.micro.booking.requests.BookingRequest;
import com.micro.booking.service.BookingService;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@WebFluxTest(controllers = BookingController.class)
class BookingControllerTest {

    @Autowired
    private WebTestClient webTestClient;

    @MockBean
    private BookingService bookingService;

    /* ---------- POST /booking ---------- */

    @Test
    void bookFlight_success() {
        when(bookingService.bookFlight(anyString(), any()))
                .thenReturn(Mono.just(new Ticket()));

        webTestClient.post()
                .uri("/api/flight/booking/F1")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(validBookingRequest())
                .exchange()
                .expectStatus().isCreated();
    }

    @Test
    void bookFlight_notFound() {
        when(bookingService.bookFlight(anyString(), any()))
                .thenReturn(Mono.error(new ResourceNotFoundException("NF")));

        webTestClient.post()
                .uri("/api/flight/booking/F1")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(validBookingRequest())
                .exchange()
                .expectStatus().isNotFound();
    }

    @Test
    void bookFlight_unprocessable() {
        when(bookingService.bookFlight(anyString(), any()))
                .thenReturn(Mono.error(new UnprocessableException("ERR")));

        webTestClient.post()
                .uri("/api/flight/booking/F1")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(validBookingRequest())
                .exchange()
                .expectStatus().isEqualTo(422);
    }

    @Test
    void bookFlight_runtimeException() {
        when(bookingService.bookFlight(anyString(), any()))
                .thenReturn(Mono.error(new RuntimeException("Down")));

        webTestClient.post()
                .uri("/api/flight/booking/F1")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(validBookingRequest())
                .exchange()
                .expectStatus().isEqualTo(503);
    }

    /* ---------- GET /ticket ---------- */

    @Test
    void getTicket_success() {
        when(bookingService.getTicketByPnr("PNR"))
                .thenReturn(Mono.just(new Ticket()));

        webTestClient.get()
                .uri("/api/flight/ticket/PNR")
                .exchange()
                .expectStatus().isOk();
    }

    @Test
    void getTicket_notFound() {
        when(bookingService.getTicketByPnr("PNR"))
                .thenReturn(Mono.error(new ResourceNotFoundException("NF")));

        webTestClient.get()
                .uri("/api/flight/ticket/PNR")
                .exchange()
                .expectStatus().isNotFound();
    }

    /* ---------- GET /booking/history ---------- */

    @Test
    void bookingHistory_empty() {
        when(bookingService.getBookingHistory("a@b.com"))
                .thenReturn(Flux.empty());

        webTestClient.get()
                .uri("/api/flight/booking/history/a@b.com")
                .exchange()
                .expectStatus().isNotFound();
    }

    @Test
    void bookingHistory_success() {
        when(bookingService.getBookingHistory("a@b.com"))
                .thenReturn(Flux.just(new Ticket()));

        webTestClient.get()
                .uri("/api/flight/booking/history/a@b.com")
                .exchange()
                .expectStatus().isOk();
    }

    /* ---------- DELETE /booking/cancel ---------- */

    @Test
    void cancelTicket_success() {
        when(bookingService.cancelTicket("PNR"))
                .thenReturn(Mono.just("Cancelled"));

        webTestClient.delete()
                .uri("/api/flight/booking/cancel/PNR")
                .exchange()
                .expectStatus().isOk();
    }

    @Test
    void cancelTicket_notFound() {
        when(bookingService.cancelTicket("PNR"))
                .thenReturn(Mono.error(new ResourceNotFoundException("NF")));

        webTestClient.delete()
                .uri("/api/flight/booking/cancel/PNR")
                .exchange()
                .expectStatus().isNotFound();
    }

    @Test
    void cancelTicket_unprocessable() {
        when(bookingService.cancelTicket("PNR"))
                .thenReturn(Mono.error(new UnprocessableException("ERR")));

        webTestClient.delete()
                .uri("/api/flight/booking/cancel/PNR")
                .exchange()
                .expectStatus().isEqualTo(422);
    }

    /* ---------- helper ---------- */

    private BookingRequest validBookingRequest() {
        BookingRequest r = new BookingRequest();
        r.setCustomerName("Neha");
        r.setCustomerEmail("neha@example.com");
        r.setTotalSeats(1);

        Passenger p = new Passenger();
        p.setName("A");
        p.setAge(22);

        r.setPassenger(List.of(p));
        return r;
    }
}