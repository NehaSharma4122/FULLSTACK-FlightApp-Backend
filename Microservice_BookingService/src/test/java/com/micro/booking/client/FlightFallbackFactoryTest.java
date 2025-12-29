package com.micro.booking.client;

import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class FlightFallbackFactoryTest {

    private final FlightFallbackFactory factory = new FlightFallbackFactory();

    @Test
    void getFlightById_shouldThrowRuntimeException() {
        Throwable cause = new RuntimeException("Service down");

        FlightClient fallbackClient = factory.create(cause);

        assertThrows(RuntimeException.class, () ->
                fallbackClient.getFlightById("FL123"));
    }

    @Test
    void updateAvailableSeats_shouldThrowRuntimeException() {
        Throwable cause = new RuntimeException("Service down");

        FlightClient fallbackClient = factory.create(cause);

        assertThrows(RuntimeException.class, () ->
                fallbackClient.updateAvailableSeats("FL123", 10));
    }
}
