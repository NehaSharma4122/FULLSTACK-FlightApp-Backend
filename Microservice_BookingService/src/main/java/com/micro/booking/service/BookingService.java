package com.micro.booking.service;

import com.micro.booking.entity.Ticket;
import com.micro.booking.requests.BookingRequest;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface BookingService {
	Mono<Ticket> bookFlight(String flightId, BookingRequest bookingRequest);
	Mono<Ticket> getTicketByPnr(String pnr);
    Flux<Ticket> getBookingHistory(String email);
    Mono<String> cancelTicket(String pnr);
}
