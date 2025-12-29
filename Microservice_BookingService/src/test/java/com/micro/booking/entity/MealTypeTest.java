package com.micro.booking.entity;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class MealTypeTest {

    @Test
    void enumValues() {
        assertThat(MealType.VEG).isNotNull();
        assertThat(MealType.NON_VEG).isNotNull();
        assertThat(MealType.BOTH).isNotNull();
    }
}
