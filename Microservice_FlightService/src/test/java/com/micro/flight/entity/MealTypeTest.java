package com.micro.flight.entity;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class MealTypeTest {

    @Test
    void enumValuesExist() {
        assertThat(MealType.BOTH).isNotNull();
        assertThat(MealType.VEG).isNotNull();
        assertThat(MealType.NON_VEG).isNotNull();
    }

    @Test
    void valueOfWorks() {
        MealType meal = MealType.valueOf("BOTH");
        assertThat(meal).isEqualTo(MealType.BOTH);
    }
}
