package com.micro.flight.requests;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.LocalDateTime;

import org.junit.jupiter.api.Test;

class InternalFlightRequestTest {

    @Test
    void testGettersAndSetters() {
        InternalFlightRequest req = new InternalFlightRequest();

        LocalDateTime now = LocalDateTime.now();

        req.setId("F101");
        req.setAvailableSeats(120);
        req.setDeparture(now);

        assertThat(req.getId()).isEqualTo("F101");
        assertThat(req.getAvailableSeats()).isEqualTo(120);
        assertThat(req.getDeparture()).isEqualTo(now);
    }

    @Test
    void testEqualsAndHashCode() {
        InternalFlightRequest r1 = new InternalFlightRequest();
        r1.setId("F1");

        InternalFlightRequest r2 = new InternalFlightRequest();
        r2.setId("F1");

        assertThat(r1).isEqualTo(r2);
        assertThat(r1.hashCode()).isEqualTo(r2.hashCode());
    }

    @Test
    void testToString() {
        InternalFlightRequest req = new InternalFlightRequest();
        req.setId("F1");

        assertThat(req.toString()).contains("F1");
    }
    
    @Test
    void testEqualsAndHashCode_allBranches() {

        LocalDateTime time = LocalDateTime.now().plusDays(1);

        InternalFlightRequest r1 = new InternalFlightRequest();
        r1.setId("F1");
        r1.setAvailableSeats(100);
        r1.setDeparture(time);

        InternalFlightRequest r2 = new InternalFlightRequest();
        r2.setId("F1");
        r2.setAvailableSeats(100);
        r2.setDeparture(time);

        InternalFlightRequest r3 = new InternalFlightRequest();
        r3.setId("F2");
        r3.setAvailableSeats(50);
        r3.setDeparture(time.plusHours(1));

        assertThat(r1.equals(r1)).isTrue();
        assertThat(r1.equals(null)).isFalse();
        assertThat(r1.equals("string")).isFalse();
        assertThat(r1.equals(r2)).isTrue();
        assertThat(r1.hashCode()).isEqualTo(r2.hashCode());
        assertThat(r1.equals(r3)).isFalse();
    }
    @Test
    void testEquals_nullFields_and_canEqual() {

        InternalFlightRequest r1 = new InternalFlightRequest();
        InternalFlightRequest r2 = new InternalFlightRequest();

        assertThat(r1.equals(r2)).isTrue();
        assertThat(r1.hashCode()).isEqualTo(r2.hashCode());

        assertThat(r1.canEqual(r2)).isTrue();
        assertThat(r1.canEqual("string")).isFalse();

        r1.setAvailableSeats(10);
        assertThat(r1.equals(r2)).isFalse();

        assertThat(r1.equals(null)).isFalse();
    }

}
