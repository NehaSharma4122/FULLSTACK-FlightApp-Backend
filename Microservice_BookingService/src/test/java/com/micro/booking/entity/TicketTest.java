package com.micro.booking.entity;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.LocalDateTime;
import java.util.List;

import org.junit.jupiter.api.Test;

class TicketTest {

    private Ticket createTicket() {
        Passenger p = new Passenger("1", "Neha", "Female", 22);

        return new Ticket(
                "PNR123",
                "Neha Sharma",
                "neha@example.com",
                "FL123",
                1,
                List.of(p),
                MealType.VEG,
                "A1",
                LocalDateTime.now(),
                "CONFIRMED"
        );
    }

    @Test
    void equals_sameObject_true() {
        Ticket ticket = createTicket();
        assertThat(ticket.equals(ticket)).isTrue();
    }

    @Test
    void equals_null_false() {
        Ticket ticket = createTicket();
        assertThat(ticket.equals(null)).isFalse();
    }

    @Test
    void equals_differentClass_false() {
        Ticket ticket = createTicket();
        assertThat(ticket.equals("NOT_A_TICKET")).isFalse();
    }

    @Test
    void equals_sameData_true_and_hashCode_same() {
        Ticket t1 = createTicket();
        Ticket t2 = createTicket();

        assertThat(t1).isEqualTo(t2);
        assertThat(t1.hashCode()).isEqualTo(t2.hashCode());
    }

    @Test
    void equals_differentData_false() {
        Ticket t1 = createTicket();
        Ticket t2 = createTicket();
        t2.setPnr("DIFFERENT_PNR");

        assertThat(t1).isNotEqualTo(t2);
    }

    @Test
    void equals_canEqual_branch_covered() {
        Ticket ticket = createTicket();
        Object other = new Object();

        assertThat(ticket.equals(other)).isFalse();
    }

    @Test
    void hashCode_shouldBeStable() {
        Ticket ticket = createTicket();
        int hash1 = ticket.hashCode();
        int hash2 = ticket.hashCode();

        assertThat(hash1).isEqualTo(hash2);
    }

    @Test
    void lombokGettersSettersCovered() {
        Ticket ticket = new Ticket();

        ticket.setPnr("PNR1");
        ticket.setCustomerName("Neha");
        ticket.setCustomerEmail("neha@example.com");
        ticket.setFlightId("FL1");
        ticket.setNumSeats(1);
        ticket.setPassenger(List.of(new Passenger()));
        ticket.setMealpref(MealType.BOTH);
        ticket.setSeatNumber("B1");
        ticket.setBookingDate(LocalDateTime.now());
        ticket.setStatus("CONFIRMED");

        assertThat(ticket.getPnr()).isEqualTo("PNR1");
        assertThat(ticket.getCustomerName()).isEqualTo("Neha");
        assertThat(ticket.getCustomerEmail()).isEqualTo("neha@example.com");
        assertThat(ticket.getFlightId()).isEqualTo("FL1");
        assertThat(ticket.getNumSeats()).isEqualTo(1);
        assertThat(ticket.getPassenger()).isNotNull();
        assertThat(ticket.getMealpref()).isEqualTo(MealType.BOTH);
        assertThat(ticket.getSeatNumber()).isEqualTo("B1");
        assertThat(ticket.getStatus()).isEqualTo("CONFIRMED");
    }

    @Test
    void toString_shouldContainKeyFields() {
        Ticket ticket = createTicket();
        String value = ticket.toString();

        assertThat(value).contains("PNR123");
        assertThat(value).contains("Neha Sharma");
        assertThat(value).contains("CONFIRMED");
    }

    @Test
    void allArgsConstructor_shouldWork() {
        Ticket ticket = new Ticket(
                "PNR999",
                "Test User",
                "test@test.com",
                "FL9",
                2,
                List.of(),
                MealType.NON_VEG,
                "C3",
                LocalDateTime.now(),
                "CONFIRMED"
        );

        assertThat(ticket.getPnr()).isEqualTo("PNR999");
        assertThat(ticket.getMealpref()).isEqualTo(MealType.NON_VEG);
    }
}
