package com.micro.booking.event;

import java.time.LocalDateTime;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class BookingEvent {
	private String type;      
    private String pnr;
    private String email;
    private String flightId;
    private int seats;
    private LocalDateTime time;
}
