package com.micro.flight.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.micro.flight.entity.Flight;
import com.micro.flight.exception.ResourceNotFoundException;
import com.micro.flight.repository.FlightRepository;
import com.micro.flight.requests.InternalFlightRequest;

import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

@Service
public class InternalFlightServiceImpl implements InternalFlightService{

	 @Autowired
	    private FlightRepository flightRepository;

	    @Override
	    public Mono<InternalFlightRequest> getFlightById(String flightId) {

	        return flightRepository.findById(flightId)
	                .switchIfEmpty(Mono.error(
	                        new ResourceNotFoundException("Flight not found")))
	                .map(flight -> {
	                    InternalFlightRequest dto = new InternalFlightRequest();
	                    dto.setId(flight.getId());
	                    dto.setAvailableSeats(flight.getAvailableSeats());
	                    dto.setDeparture(flight.getDeparture());
	                    return dto;
	                });
	    }

	    @Override
	    public Mono<Void> updateAvailableSeats(String flightId, int seats) {

	        return flightRepository.findById(flightId)
	                .switchIfEmpty(Mono.error(
	                        new ResourceNotFoundException("Flight not found")))
	                .flatMap(flight -> {
	                    flight.setAvailableSeats(seats);
	                    return flightRepository.save(flight);
	                })
	                .then();
	    }
	

}
