package com.micro.booking.requests;

import java.util.List;

import com.micro.booking.entity.MealType;
import com.micro.booking.entity.Passenger;
import com.micro.booking.requests.BookingRequest;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class BookingRequest {
	@NotBlank(message="Name is required")
    private String customerName;

    @NotBlank(message="Email is required")
    @Email(message="Invalid email")
    private String customerEmail;

    @NotNull(message="Number of seats required")
    @Min(value=1,message="At least 1 seat required")
    private Integer totalSeats;

    @NotNull(message="Passenger Details are required.")
    private List<Passenger> passenger;

    private MealType mealpref;
    private String seatNumber;
	

}
