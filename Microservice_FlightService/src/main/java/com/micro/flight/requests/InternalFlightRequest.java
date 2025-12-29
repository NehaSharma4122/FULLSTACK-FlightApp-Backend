package com.micro.flight.requests;

import java.time.LocalDateTime;

import lombok.Data;

@Data
public class InternalFlightRequest {
    private String id;
    private int availableSeats;
    private LocalDateTime departure;

}
