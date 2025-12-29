package com.micro.booking.event;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.LocalDateTime;

import org.junit.jupiter.api.Test;

class BookingEventTest {

    private BookingEvent createEvent() {
        return new BookingEvent(
                "BOOKED",
                "PNR123",
                "neha@example.com",
                "FL123",
                2,
                LocalDateTime.now()
        );
    }

    @Test
    void constructor_allArgs_shouldSetFields() {
        BookingEvent e = createEvent();

        assertThat(e.getType()).isEqualTo("BOOKED");
        assertThat(e.getPnr()).isEqualTo("PNR123");
        assertThat(e.getEmail()).isEqualTo("neha@example.com");
        assertThat(e.getFlightId()).isEqualTo("FL123");
        assertThat(e.getSeats()).isEqualTo(2);
        assertThat(e.getTime()).isNotNull();
    }

    @Test
    void equals_sameObject_true() {
        BookingEvent e = createEvent();
        assertThat(e.equals(e)).isTrue();
    }

    @Test
    void equals_null_false() {
        BookingEvent e = createEvent();
        assertThat(e.equals(null)).isFalse();
    }

    @Test
    void equals_differentClass_false() {
        BookingEvent e = createEvent();
        assertThat(e.equals("NOT_EVENT")).isFalse();
    }

    @Test
    void equals_sameData_true() {
        BookingEvent e1 = createEvent();
        BookingEvent e2 = createEvent();

        assertThat(e1).isEqualTo(e2);
        assertThat(e1.hashCode()).isEqualTo(e2.hashCode());
    }

    @Test
    void equals_differentData_false() {
        BookingEvent e1 = createEvent();
        BookingEvent e2 = createEvent();
        e2.setType("CANCELLED");

        assertThat(e1).isNotEqualTo(e2);
    }

    @Test
    void hashCode_shouldNotThrow() {
        BookingEvent e = createEvent();
        assertThat(e.hashCode()).isNotZero();
    }

    @Test
    void toString_shouldContainPnr() {
        BookingEvent e = createEvent();
        assertThat(e.toString()).contains("PNR123");
    }

    @Test
    void lombokSettersGettersCovered() {
        BookingEvent e = new BookingEvent();

        e.setType("CANCELLED");
        e.setPnr("PNR9");
        e.setEmail("x@test.com");
        e.setFlightId("FL9");
        e.setSeats(1);
        e.setTime(LocalDateTime.now());

        assertThat(e.getType()).isEqualTo("CANCELLED");
        assertThat(e.getPnr()).isEqualTo("PNR9");
        assertThat(e.getEmail()).isEqualTo("x@test.com");
        assertThat(e.getFlightId()).isEqualTo("FL9");
        assertThat(e.getSeats()).isEqualTo(1);
        assertThat(e.getTime()).isNotNull();
    }
}
