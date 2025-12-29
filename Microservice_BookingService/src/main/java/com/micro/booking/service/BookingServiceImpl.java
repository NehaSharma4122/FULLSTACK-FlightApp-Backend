package com.micro.booking.service;

import java.time.LocalDateTime;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.micro.booking.client.FlightClient;
import com.micro.booking.entity.Passenger;
import com.micro.booking.entity.Ticket;
import com.micro.booking.event.BookingEvent;
import com.micro.booking.exception.ResourceNotFoundException;
import com.micro.booking.exception.ServiceUnavailableException;
import com.micro.booking.exception.UnprocessableException;
import com.micro.booking.kafka.BookingEventProducer;
import com.micro.booking.repository.TicketRepository;
import com.micro.booking.requests.BookingRequest;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

@Service
public class BookingServiceImpl implements BookingService {

    @Autowired
    private TicketRepository ticketRepository;

    @Autowired
    private FlightClient flightClient;

    @Autowired
    private BookingEventProducer bookingEventProducer;

    @Override
    public Mono<Ticket> bookFlight(String flightId, BookingRequest bookingRequest) {

        return Mono.fromCallable(() -> {
                    try {
                        return flightClient.getFlightById(flightId);
                    }  catch (ServiceUnavailableException e) {
                        throw new ServiceUnavailableException("Flight server down"); 
                    }catch (Exception e) {
                        throw new ResourceNotFoundException("Flight not found with ID: " + flightId);
                    }
                })
                .subscribeOn(Schedulers.boundedElastic())

                .flatMap(flight -> {
                    if (flight == null || flight.getId() == null) {
                        return Mono.error(new ResourceNotFoundException(
                                "Flight not found with ID: " + flightId));
                    }

                    int requestedSeats = bookingRequest.getTotalSeats();

                    if (flight.getAvailableSeats() < requestedSeats) {
                        return Mono.error(new UnprocessableException(
                                "Not enough seats available. Requested: " + requestedSeats +
                                ", available: " + flight.getAvailableSeats()));
                    }

                    Ticket ticket = new Ticket();
                    ticket.setPnr(generatePNR());
                    ticket.setFlightId(flightId);
                    ticket.setCustomerName(bookingRequest.getCustomerName());
                    ticket.setCustomerEmail(bookingRequest.getCustomerEmail());
                    ticket.setNumSeats(requestedSeats);
                    ticket.setMealpref(bookingRequest.getMealpref());
                    ticket.setSeatNumber(bookingRequest.getSeatNumber());
                    ticket.setBookingDate(LocalDateTime.now());
                    ticket.setStatus("CONFIRMED");

                    if (bookingRequest.getPassenger() != null) {
                        ticket.setPassenger(
                                bookingRequest.getPassenger()
                                        .stream()
                                        .map(this::convertToPassenger)
                                        .toList()
                        );
                    }

                    return Mono.fromRunnable(() ->
                            flightClient.updateAvailableSeats(
                                    flightId,
                                    flight.getAvailableSeats() - requestedSeats))
                            .subscribeOn(Schedulers.boundedElastic())

                            .then(ticketRepository.save(ticket))

                            .doOnSuccess(savedTicket ->
                                    bookingEventProducer.sendBookingEvent(
                                            new BookingEvent(
                                                    "BOOKED",
                                                    savedTicket.getPnr(),
                                                    savedTicket.getCustomerEmail(),
                                                    savedTicket.getFlightId(),
                                                    savedTicket.getNumSeats(),
                                                    LocalDateTime.now()
                                            )
                                    )
                            );
                });
    }


    @Override
    public Mono<Ticket> getTicketByPnr(String pnr) {
        if (pnr == null || pnr.trim().isEmpty()) {
            return Mono.error(new ResourceNotFoundException("PNR cannot be null or empty"));
        }
        return ticketRepository.findByPnr(pnr.trim())
                .switchIfEmpty(Mono.error(new ResourceNotFoundException("Ticket not found with PNR: " + pnr)));
    }

    @Override
    public Flux<Ticket> getBookingHistory(String email) {
        if (email == null || email.trim().isEmpty()) {
            return Flux.empty();
        }
        return ticketRepository.findByCustomerEmail(email.trim());
    }

    @Override
    public Mono<String> cancelTicket(String pnr) {

        if (pnr == null || pnr.trim().isEmpty()) {
            return Mono.error(new ResourceNotFoundException("PNR cannot be null or empty"));
        }

        return ticketRepository.findByPnr(pnr.trim())
                .switchIfEmpty(Mono.error(
                        new ResourceNotFoundException("Ticket not found with PNR: " + pnr)))

                .flatMap(ticket ->
                        Mono.fromCallable(() -> {
                            try {
                                return flightClient.getFlightById(ticket.getFlightId());
                            } catch (Exception e) {
                                throw new ResourceNotFoundException(
                                        "Flight associated with this ticket no longer exists.");
                            }
                        })
                        .subscribeOn(Schedulers.boundedElastic())

                        .flatMap(flight -> {

                            if (LocalDateTime.now().plusHours(24)
                                    .isAfter(flight.getDeparture())) {
                                return Mono.error(new UnprocessableException(
                                        "Cancellation not allowed within 24 hours of departure"));
                            }

                            Mono<Void> updateSeats =
                                    Mono.fromRunnable(() ->
                                            flightClient.updateAvailableSeats(
                                                    flight.getId(),
                                                    flight.getAvailableSeats() + ticket.getNumSeats()))
                                    .subscribeOn(Schedulers.boundedElastic())
                                    .then();

                            // delete ticket
                            Mono<Void> deleteTicket =
                                    ticketRepository.deleteById(ticket.getPnr());

                            return updateSeats
                                    .then(deleteTicket)
                                    .doOnSuccess(v ->
                                            bookingEventProducer.sendBookingEvent(
                                                    new BookingEvent(
                                                            "CANCELLED",
                                                            ticket.getPnr(),
                                                            ticket.getCustomerEmail(),
                                                            ticket.getFlightId(),
                                                            ticket.getNumSeats(),
                                                            LocalDateTime.now()
                                                    )
                                            )
                                    )
                                    .thenReturn("Ticket cancelled and removed successfully");
                        })
                );
    }



    private String generatePNR() {
        return UUID.randomUUID().toString().substring(0, 8).toUpperCase();
    }

    private Passenger convertToPassenger(Passenger req) {
        Passenger passenger = new Passenger();
        passenger.setName(req.getName());
        passenger.setGender(req.getGender());
        passenger.setAge(req.getAge());
        return passenger;
    }
}
