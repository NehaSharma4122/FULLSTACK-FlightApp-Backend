package com.micro.flight.service;

import java.time.LocalDate;
import java.time.LocalDateTime;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.micro.flight.entity.Flight;
import com.micro.flight.exception.ResourceNotFoundException;
import com.micro.flight.exception.UnprocessableException;
import com.micro.flight.repository.FlightRepository;
import com.micro.flight.requests.SearchRequests;
import com.micro.flight.requests.Trip;
import com.micro.flight.service.FlightService;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Service
public class FlightServiceImpl implements FlightService {
	@Autowired
	private FlightRepository flightRepository;

	@Override
	public Mono<Flight> addFlight(Flight flight) {
		return flightRepository.save(flight);
	}


    @Override
    public Flux<Flight> searchFlights(SearchRequests searchRequest) {

        Trip tripType = searchRequest.getTripType();
        LocalDate travelDate = searchRequest.getTravelDate();

        LocalDateTime dayStart = travelDate.atStartOfDay();
        LocalDateTime dayEnd = dayStart.plusDays(1);

        if (tripType == Trip.ONE_WAY) {
            return flightRepository.findByFromPlaceAndToPlaceAndDepartureBetween(
                    searchRequest.getFromPlace(),
                    searchRequest.getToPlace(),
                    dayStart,
                    dayEnd
            );
        }

        else if (tripType == Trip.ROUND_TRIP) {

            if (searchRequest.getReturnDate() == null) {
                return Flux.error(new UnprocessableException("Return date is required for round trip"));
            }

            if (searchRequest.getReturnDate().isBefore(travelDate)) {
                return Flux.error(new UnprocessableException("Return date cannot be before departure date"));
            }

            LocalDateTime returnStart = searchRequest.getReturnDate().atStartOfDay();
            LocalDateTime returnEnd = returnStart.plusDays(1);

            Flux<Flight> outbound =
                    flightRepository.findByFromPlaceAndToPlaceAndDepartureBetween(
                            searchRequest.getFromPlace(),
                            searchRequest.getToPlace(),
                            dayStart,
                            dayEnd
                    );

            Flux<Flight> inbound =
                    flightRepository.findByFromPlaceAndToPlaceAndDepartureBetween(
                            searchRequest.getToPlace(),
                            searchRequest.getFromPlace(),
                            returnStart,
                            returnEnd
                    );

            return Flux.concat(outbound, inbound);
        }

        return flightRepository.findByFromPlaceAndToPlaceAndDepartureBetween(
                searchRequest.getFromPlace(),
                searchRequest.getToPlace(),
                dayStart,
                dayEnd
        );
    }

    @Override
    public Mono<Flight> getFlightById(String id) {
        return flightRepository.findById(id)
                .switchIfEmpty(Mono.error(new ResourceNotFoundException("Flight not found with id: " + id)));
    }

    @Override
    public Flux<Flight> getAllFlights() {
        return flightRepository.findAll();
    }

}

