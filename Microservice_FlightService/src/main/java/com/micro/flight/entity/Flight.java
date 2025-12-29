package com.micro.flight.entity;

import java.time.LocalDateTime;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import com.micro.flight.entity.MealType;
import com.fasterxml.jackson.annotation.JsonFormat;

import jakarta.validation.constraints.Future;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Document(collection = "flight")
public class Flight {

	@Id
    private String id;

    @NotBlank
    private String airline_name;

    private String airline_logo;

    @NotBlank
    private String flightNumber;

    @NotBlank
    private String fromPlace;

    @NotBlank
    private String toPlace;

    @JsonFormat(pattern = "yyyy-MM-dd'T'HH:mm:ss")
    @Future(message = "Travel date must be in the future")
    private LocalDateTime departure;

    @JsonFormat(pattern = "yyyy-MM-dd'T'HH:mm:ss")
    @Future(message = "Travel date must be in the future")
    private LocalDateTime arrival;

    @Min(1)
    private double price;

    private int availableSeats;

    private MealType mealType;

	
    
}

