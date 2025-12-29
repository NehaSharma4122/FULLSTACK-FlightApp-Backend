package com.micro.booking.repository;

import org.springframework.data.mongodb.repository.ReactiveMongoRepository;
import org.springframework.stereotype.Repository;

import com.micro.booking.entity.Ticket;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Repository
public interface TicketRepository extends ReactiveMongoRepository<Ticket, String>{
	Flux<Ticket> findByCustomerEmail(String customerEmail);
	Mono<Ticket> findByPnr(String pnr);
}
