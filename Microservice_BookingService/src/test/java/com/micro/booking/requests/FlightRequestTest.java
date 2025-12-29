package com.micro.booking.requests;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.LocalDateTime;

import org.junit.jupiter.api.Test;

class FlightRequestTest {

    private FlightRequest createRequest() {
        FlightRequest r = new FlightRequest();
        r.setId("FL1");
        r.setAvailableSeats(100);
        r.setDeparture(LocalDateTime.now().plusDays(1));
        return r;
    }

    @Test
    void equals_sameObject_true() {
        FlightRequest r = createRequest();
        assertThat(r.equals(r)).isTrue();
    }

    @Test
    void equals_null_false() {
        FlightRequest r = createRequest();
        assertThat(r.equals(null)).isFalse();
    }

    @Test
    void equals_differentClass_false() {
        FlightRequest r = createRequest();
        assertThat(r.equals("NOT_FLIGHT")).isFalse();
    }

    @Test
    void equals_sameData_true() {
        FlightRequest r1 = createRequest();
        FlightRequest r2 = createRequest();

        assertThat(r1).isEqualTo(r2);
        assertThat(r1.hashCode()).isEqualTo(r2.hashCode());
    }

    @Test
    void equals_differentData_false() {
        FlightRequest r1 = createRequest();
        FlightRequest r2 = createRequest();
        r2.setAvailableSeats(50);

        assertThat(r1).isNotEqualTo(r2);
    }

    @Test
    void hashCode_shouldNotThrow() {
        FlightRequest r = createRequest();
        assertThat(r.hashCode()).isNotZero();
    }

    @Test
    void toString_shouldContainId() {
        FlightRequest r = createRequest();
        assertThat(r.toString()).contains("FL1");
    }

    @Test
    void lombokSettersGettersCovered() {
        FlightRequest r = new FlightRequest();

        r.setId("ID2");
        r.setAvailableSeats(10);
        r.setDeparture(LocalDateTime.now());

        assertThat(r.getId()).isEqualTo("ID2");
        assertThat(r.getAvailableSeats()).isEqualTo(10);
        assertThat(r.getDeparture()).isNotNull();
    }
}
