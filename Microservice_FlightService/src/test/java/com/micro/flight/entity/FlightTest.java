package com.micro.flight.entity;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.LocalDateTime;
import java.util.Set;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class FlightTest {

    private Validator validator;

    @BeforeEach
    void setup() {
        ValidatorFactory factory = Validation.buildDefaultValidatorFactory();
        validator = factory.getValidator();
    }

    @Test
    void testNoArgsConstructor() {
        Flight flight = new Flight();
        assertThat(flight).isNotNull();
    }

    @Test
    void testAllArgsConstructor() {
        LocalDateTime future = LocalDateTime.now().plusDays(1);

        Flight flight = new Flight(
                "F1",
                "INDIGO",
                "logo.png",
                "6E123",
                "Mumbai",
                "Delhi",
                future,
                future.plusHours(2),
                5000,
                120,
                MealType.BOTH
        );

        assertThat(flight.getId()).isEqualTo("F1");
        assertThat(flight.getAirline_name()).isEqualTo("INDIGO");
        assertThat(flight.getMealType()).isEqualTo(MealType.BOTH);
    }


    @Test
    void testGettersSettersEqualsHashCodeToString() {
        Flight f1 = new Flight();
        Flight f2 = new Flight();

        f1.setAirline_name("INDIGO");
        f2.setAirline_name("INDIGO");

        assertThat(f1.getAirline_name()).isEqualTo("INDIGO");
        assertThat(f1).isEqualTo(f2);
        assertThat(f1.hashCode()).isEqualTo(f2.hashCode());
        assertThat(f1.toString()).contains("INDIGO");
    }


    @Test
    void validFlight_shouldHaveNoViolations() {
        Flight flight = validFlight();

        Set<ConstraintViolation<Flight>> violations =
                validator.validate(flight);

        assertThat(violations).isEmpty();
    }


    @Test
    void invalidFlight_shouldFailValidation() {
        Flight flight = new Flight(); // missing required fields

        Set<ConstraintViolation<Flight>> violations =
                validator.validate(flight);

        assertThat(violations).isNotEmpty();
    }

    @Test
    void pastDepartureDate_shouldFailFutureValidation() {
        Flight flight = validFlight();
        flight.setDeparture(LocalDateTime.now().minusDays(1));

        Set<ConstraintViolation<Flight>> violations =
                validator.validate(flight);

        assertThat(violations).isNotEmpty();
    }

    @Test
    void priceLessThanOne_shouldFailMinValidation() {
        Flight flight = validFlight();
        flight.setPrice(0);

        Set<ConstraintViolation<Flight>> violations =
                validator.validate(flight);

        assertThat(violations).isNotEmpty();
    }


    private Flight validFlight() {
        LocalDateTime future = LocalDateTime.now().plusDays(1);

        Flight flight = new Flight();
        flight.setAirline_name("INDIGO");
        flight.setFlightNumber("6E123");
        flight.setFromPlace("Mumbai");
        flight.setToPlace("Delhi");
        flight.setDeparture(future);
        flight.setArrival(future.plusHours(2));
        flight.setPrice(5500);
        flight.setAvailableSeats(120);
        flight.setMealType(MealType.BOTH);

        return flight;
    }
    
    @Test
    void testEqualsAndHashCode_allBranches() {

        LocalDateTime future = LocalDateTime.now().plusDays(1);

        Flight f1 = new Flight(
                "1", "INDIGO", null, "6E1", "MUM", "DEL",
                future, future.plusHours(2), 5000, 100, MealType.BOTH
        );

        Flight f2 = new Flight(
                "1", "INDIGO", null, "6E1", "MUM", "DEL",
                future, future.plusHours(2), 5000, 100, MealType.BOTH
        );

        Flight f3 = new Flight(
                "2", "AIRINDIA", null, "AI1", "DEL", "MUM",
                future, future.plusHours(2), 6000, 50, MealType.VEG
        );

        assertThat(f1.equals(f1)).isTrue();

        assertThat(f1.equals(null)).isFalse();

        assertThat(f1.equals("string")).isFalse();

        assertThat(f1.equals(f2)).isTrue();
        assertThat(f1.hashCode()).isEqualTo(f2.hashCode());

        assertThat(f1.equals(f3)).isFalse();
    }
    
    @Test
    void testEquals_canEqual_and_nullFields() {

        LocalDateTime future = LocalDateTime.now().plusDays(1);

        Flight f1 = new Flight();
        Flight f2 = new Flight();

        assertThat(f1.equals(f2)).isTrue();
        assertThat(f1.hashCode()).isEqualTo(f2.hashCode());

        assertThat(f1.canEqual(f2)).isTrue();
        assertThat(f1.canEqual("string")).isFalse();

        f1.setAirline_name("INDIGO");
        assertThat(f1.equals(f2)).isFalse();

        assertThat(f1.equals(null)).isFalse();
    }

}
