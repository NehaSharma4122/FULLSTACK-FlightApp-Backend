package com.micro.flight.requests;

import java.time.LocalDate;

import com.micro.flight.requests.Trip;
import com.fasterxml.jackson.annotation.JsonFormat;

import jakarta.validation.constraints.Future;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SearchRequests {
	@NotBlank(message = "From place is required")
    private String fromPlace;

    @NotBlank(message = "To place is required")
    private String toPlace;

    @NotNull(message = "Travel date is required")
    @Future(message = "Travel date must be in the future")
    @JsonFormat(pattern = "yyyy-MM-dd")
    private LocalDate travelDate;

    @JsonFormat(pattern = "yyyy-MM-dd")
    private LocalDate returnDate; 

    @NotNull(message = "Trip type is required")
    private Trip tripType;

    
}