package com.micro.booking.entity;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class PassengerTest {

    private Passenger createPassenger() {
        return new Passenger("1", "Neha", "Female", 22);
    }

    @Test
    void constructor_allArgs_shouldSetFields() {
        Passenger p = new Passenger("1", "Neha", "Female", 22);

        assertThat(p.getId()).isEqualTo("1");
        assertThat(p.getName()).isEqualTo("Neha");
        assertThat(p.getGender()).isEqualTo("Female");
        assertThat(p.getAge()).isEqualTo(22);
    }

    @Test
    void equals_sameObject_true() {
        Passenger p = createPassenger();
        assertThat(p.equals(p)).isTrue();
    }

    @Test
    void equals_null_false() {
        Passenger p = createPassenger();
        assertThat(p.equals(null)).isFalse();
    }

    @Test
    void equals_differentClass_false() {
        Passenger p = createPassenger();
        assertThat(p.equals("NOT_PASSENGER")).isFalse();
    }

    @Test
    void equals_sameData_true() {
        Passenger p1 = createPassenger();
        Passenger p2 = createPassenger();

        assertThat(p1).isEqualTo(p2);
        assertThat(p1.hashCode()).isEqualTo(p2.hashCode());
    }

    @Test
    void equals_differentData_false() {
        Passenger p1 = createPassenger();
        Passenger p2 = createPassenger();
        p2.setAge(30);

        assertThat(p1).isNotEqualTo(p2);
    }

    @Test
    void hashCode_shouldNotThrow() {
        Passenger p = createPassenger();
        assertThat(p.hashCode()).isNotZero();
    }

    @Test
    void toString_shouldContainName() {
        Passenger p = createPassenger();
        assertThat(p.toString()).contains("Neha");
    }

    @Test
    void lombokSettersGettersCovered() {
        Passenger p = new Passenger();

        p.setId("2");
        p.setName("A");
        p.setGender("Male");
        p.setAge(25);

        assertThat(p.getId()).isEqualTo("2");
        assertThat(p.getName()).isEqualTo("A");
        assertThat(p.getGender()).isEqualTo("Male");
        assertThat(p.getAge()).isEqualTo(25);
    }
}
