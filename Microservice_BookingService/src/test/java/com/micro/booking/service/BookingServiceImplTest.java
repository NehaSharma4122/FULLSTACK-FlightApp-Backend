package com.micro.booking.service;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.when;

import java.time.LocalDateTime;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.micro.booking.client.FlightClient;
import com.micro.booking.entity.Passenger;
import com.micro.booking.entity.Ticket;
import com.micro.booking.event.BookingEvent;
import com.micro.booking.exception.ResourceNotFoundException;
import com.micro.booking.exception.UnprocessableException;
import com.micro.booking.kafka.BookingEventProducer;
import com.micro.booking.repository.TicketRepository;
import com.micro.booking.requests.BookingRequest;
import com.micro.booking.requests.FlightRequest;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

@ExtendWith(MockitoExtension.class)
class BookingServiceImplTest {

    @Mock
    private TicketRepository ticketRepository;

    @Mock
    private FlightClient flightClient;

    @Mock
    private BookingEventProducer bookingEventProducer;

    @InjectMocks
    private BookingServiceImpl bookingService;

    /* ---------- bookFlight ---------- */

    @Test
    void bookFlight_success() {
        FlightRequest flight = new FlightRequest();
        flight.setId("F1");
        flight.setAvailableSeats(10);

        when(flightClient.getFlightById("F1")).thenReturn(flight);
        doNothing().when(flightClient)
                .updateAvailableSeats(anyString(), anyInt());

        when(ticketRepository.save(any(Ticket.class)))
                .thenAnswer(inv -> Mono.just(inv.getArgument(0)));

        doNothing().when(bookingEventProducer)
                .sendBookingEvent(any());

        BookingRequest req = new BookingRequest(
                "Neha", "n@example.com", 1,
                List.of(new Passenger()), null, null
        );

        StepVerifier.create(bookingService.bookFlight("F1", req))
                .expectNextMatches(t -> t.getStatus().equals("CONFIRMED"))
                .verifyComplete();
    }


    @Test
    void bookFlight_insufficientSeats() {
        FlightRequest flight = new FlightRequest();
        flight.setId("F1");
        flight.setAvailableSeats(0);

        when(flightClient.getFlightById("F1")).thenReturn(flight);

        BookingRequest req = new BookingRequest(
                "Neha", "n@example.com", 2,
                List.of(), null, null
        );

        StepVerifier.create(bookingService.bookFlight("F1", req))
                .expectError(UnprocessableException.class)
                .verify();
    }

    @Test
    void bookFlight_flightNotFound() {
        when(flightClient.getFlightById(anyString()))
                .thenThrow(new RuntimeException());

        StepVerifier.create(
                bookingService.bookFlight("X", new BookingRequest())
        ).expectError(ResourceNotFoundException.class)
         .verify();
    }

    /* ---------- getTicketByPnr ---------- */

    @Test
    void getTicketByPnr_success() {
        Ticket t = new Ticket();
        t.setPnr("PNR");

        when(ticketRepository.findByPnr("PNR")).thenReturn(Mono.just(t));

        StepVerifier.create(bookingService.getTicketByPnr("PNR"))
                .expectNext(t)
                .verifyComplete();
    }

    @Test
    void getTicketByPnr_invalid() {
        StepVerifier.create(bookingService.getTicketByPnr(" "))
                .expectError(ResourceNotFoundException.class)
                .verify();
    }

    /* ---------- getBookingHistory ---------- */

    @Test
    void getBookingHistory_emptyEmail() {
        StepVerifier.create(bookingService.getBookingHistory(""))
                .verifyComplete();
    }

    @Test
    void getBookingHistory_success() {
        when(ticketRepository.findByCustomerEmail("a@b.com"))
                .thenReturn(Flux.just(new Ticket()));

        StepVerifier.create(
                bookingService.getBookingHistory("a@b.com")
        ).expectNextCount(1)
         .verifyComplete();
    }

    /* ---------- cancelTicket ---------- */

    @Test
    void cancelTicket_success() {
        Ticket ticket = new Ticket();
        ticket.setPnr("PNR"); // ✅ REQUIRED
        ticket.setFlightId("F1");
        ticket.setNumSeats(1);
        ticket.setCustomerEmail("n@example.com");

        FlightRequest flight = new FlightRequest();
        flight.setId("F1");
        flight.setAvailableSeats(5);
        flight.setDeparture(LocalDateTime.now().plusDays(2));

        when(ticketRepository.findByPnr("PNR"))
                .thenReturn(Mono.just(ticket));

        when(ticketRepository.deleteById("PNR"))
                .thenReturn(Mono.empty());

        when(flightClient.getFlightById("F1"))
                .thenReturn(flight);

        doNothing().when(flightClient)
                .updateAvailableSeats(anyString(), anyInt());

        doNothing().when(bookingEventProducer)
                .sendBookingEvent(any());

        StepVerifier.create(bookingService.cancelTicket("PNR"))
                .expectNext("Ticket cancelled and removed successfully")
                .verifyComplete();
    }


    @Test
    void cancelTicket_within24Hours() {
        Ticket ticket = new Ticket();
        ticket.setFlightId("F1");
        ticket.setNumSeats(1);

        FlightRequest flight = new FlightRequest();
        flight.setDeparture(LocalDateTime.now().plusHours(1));

        when(ticketRepository.findByPnr("PNR"))
                .thenReturn(Mono.just(ticket));
        when(flightClient.getFlightById("F1"))
                .thenReturn(flight);

        StepVerifier.create(bookingService.cancelTicket("PNR"))
                .expectError(UnprocessableException.class)
                .verify();
    }
}
