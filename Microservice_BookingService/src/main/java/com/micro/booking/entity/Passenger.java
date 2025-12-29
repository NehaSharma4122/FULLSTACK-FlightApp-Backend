package com.micro.booking.entity;

import org.hibernate.validator.constraints.UUID;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import com.micro.booking.entity.Passenger;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Document(collection = "passenger")
public class Passenger {
	@UUID
    private String id;

    @NotBlank
    private String name;

    private String gender;

    @Min(1)
    private int age;
    
}