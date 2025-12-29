package com.micro.booking.requests;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.Test;

import com.micro.booking.entity.MealType;
import com.micro.booking.entity.Passenger;

class BookingRequestTest {

    private BookingRequest createRequest() {
        Passenger p = new Passenger("1", "Neha", "Female", 22);

        return new BookingRequest(
                "Neha",
                "neha@example.com",
                1,
                List.of(p),
                MealType.VEG,
                "A1"
        );
    }

    @Test
    void constructor_allArgs_shouldSetFields() {
        BookingRequest r = createRequest();

        assertThat(r.getCustomerName()).isEqualTo("Neha");
        assertThat(r.getCustomerEmail()).isEqualTo("neha@example.com");
        assertThat(r.getTotalSeats()).isEqualTo(1);
        assertThat(r.getPassenger()).isNotEmpty();
        assertThat(r.getMealpref()).isEqualTo(MealType.VEG);
        assertThat(r.getSeatNumber()).isEqualTo("A1");
    }

    @Test
    void equals_sameObject_true() {
        BookingRequest r = createRequest();
        assertThat(r.equals(r)).isTrue();
    }

    @Test
    void equals_null_false() {
        BookingRequest r = createRequest();
        assertThat(r.equals(null)).isFalse();
    }

    @Test
    void equals_differentClass_false() {
        BookingRequest r = createRequest();
        assertThat(r.equals("NOT_BOOKING_REQUEST")).isFalse();
    }

    @Test
    void equals_sameData_true() {
        BookingRequest r1 = createRequest();
        BookingRequest r2 = createRequest();

        assertThat(r1).isEqualTo(r2);
        assertThat(r1.hashCode()).isEqualTo(r2.hashCode());
    }

    @Test
    void equals_differentData_false() {
        BookingRequest r1 = createRequest();
        BookingRequest r2 = createRequest();
        r2.setTotalSeats(2);

        assertThat(r1).isNotEqualTo(r2);
    }

    @Test
    void hashCode_shouldNotThrow() {
        BookingRequest r = createRequest();
        assertThat(r.hashCode()).isNotZero();
    }

    @Test
    void toString_shouldContainCustomerName() {
        BookingRequest r = createRequest();
        assertThat(r.toString()).contains("Neha");
    }

    @Test
    void lombokSettersGettersCovered() {
        BookingRequest r = new BookingRequest();

        r.setCustomerName("A");
        r.setCustomerEmail("a@test.com");
        r.setTotalSeats(2);
        r.setPassenger(List.of(new Passenger()));
        r.setMealpref(MealType.BOTH);
        r.setSeatNumber("B1");

        assertThat(r.getCustomerName()).isEqualTo("A");
        assertThat(r.getCustomerEmail()).isEqualTo("a@test.com");
        assertThat(r.getTotalSeats()).isEqualTo(2);
        assertThat(r.getPassenger()).isNotNull();
        assertThat(r.getMealpref()).isEqualTo(MealType.BOTH);
        assertThat(r.getSeatNumber()).isEqualTo("B1");
    }
}
