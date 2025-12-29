package com.micro.booking.entity;

import java.time.LocalDateTime;
import java.util.List;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import com.micro.booking.entity.MealType;
import com.micro.booking.entity.Passenger;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

import com.fasterxml.jackson.annotation.JsonFormat;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Document(collection = "ticket")
public class Ticket {
	@Id
    private String pnr;
    
    @NotBlank
    private String customerName;

    @Email
    @NotBlank
    @Indexed
    private String customerEmail;
    
    private String flightId;    

    private Integer numSeats;

    private List<Passenger> passenger; 

    private MealType mealpref;

    private String seatNumber;

    @JsonFormat(pattern = "yyyy-MM-dd'T'HH:mm:ss")
    private LocalDateTime bookingDate;

    private String status;

}