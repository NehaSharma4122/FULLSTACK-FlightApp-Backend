package com.micro.flight.repository;

import java.time.LocalDateTime;

import org.springframework.data.mongodb.repository.ReactiveMongoRepository;
import org.springframework.stereotype.Repository;

import com.micro.flight.entity.Flight;

import reactor.core.publisher.Flux;

@Repository
public interface FlightRepository extends ReactiveMongoRepository<Flight, String>{
	 Flux<Flight> findByFromPlaceAndToPlaceAndDepartureBetween(
			 String fromPlace, String toPlace,
			 LocalDateTime departureStart, LocalDateTime departureEnd);
}

