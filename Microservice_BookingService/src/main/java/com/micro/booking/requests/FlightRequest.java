package com.micro.booking.requests;

import java.time.LocalDateTime;

import lombok.Data;

@Data
public class FlightRequest {
	private String id;
    private int availableSeats;
    private LocalDateTime departure;
}
