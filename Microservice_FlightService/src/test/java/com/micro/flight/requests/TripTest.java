package com.micro.flight.requests;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class TripTest {

    @Test
    void enumValues_shouldExist() {
        assertThat(Trip.ONE_WAY).isNotNull();
        assertThat(Trip.ROUND_TRIP).isNotNull();
    }

    @Test
    void valueOf_shouldWork() {
        Trip trip = Trip.valueOf("ONE_WAY");
        assertThat(trip).isEqualTo(Trip.ONE_WAY);
    }
}
