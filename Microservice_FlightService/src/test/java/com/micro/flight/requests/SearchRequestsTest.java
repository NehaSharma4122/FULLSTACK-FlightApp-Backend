package com.micro.flight.requests;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.LocalDate;
import java.util.Set;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class SearchRequestsTest {

    private Validator validator;

    @BeforeEach
    void setup() {
        ValidatorFactory factory = Validation.buildDefaultValidatorFactory();
        validator = factory.getValidator();
    }

    /* ---------------- VALID CASE ---------------- */

    @Test
    void validSearchRequest_shouldHaveNoViolations() {
        SearchRequests request = new SearchRequests(
                "DEL",
                "BOM",
                LocalDate.now().plusDays(1),
                null,
                Trip.ONE_WAY
        );

        Set<ConstraintViolation<SearchRequests>> violations =
                validator.validate(request);

        assertThat(violations).isEmpty();
    }

    /* ---------------- VALIDATION FAILURES ---------------- */

    @Test
    void missingFromPlace_shouldFailValidation() {
        SearchRequests request = new SearchRequests(
                null,
                "BOM",
                LocalDate.now().plusDays(1),
                null,
                Trip.ONE_WAY
        );

        Set<ConstraintViolation<SearchRequests>> violations =
                validator.validate(request);

        assertThat(violations).isNotEmpty();
    }

    @Test
    void missingToPlace_shouldFailValidation() {
        SearchRequests request = new SearchRequests(
                "DEL",
                null,
                LocalDate.now().plusDays(1),
                null,
                Trip.ONE_WAY
        );

        Set<ConstraintViolation<SearchRequests>> violations =
                validator.validate(request);

        assertThat(violations).isNotEmpty();
    }

    @Test
    void missingTravelDate_shouldFailValidation() {
        SearchRequests request = new SearchRequests(
                "DEL",
                "BOM",
                null,
                null,
                Trip.ONE_WAY
        );

        Set<ConstraintViolation<SearchRequests>> violations =
                validator.validate(request);

        assertThat(violations).isNotEmpty();
    }

    @Test
    void pastTravelDate_shouldFailFutureValidation() {
        SearchRequests request = new SearchRequests(
                "DEL",
                "BOM",
                LocalDate.now().minusDays(1),
                null,
                Trip.ONE_WAY
        );

        Set<ConstraintViolation<SearchRequests>> violations =
                validator.validate(request);

        assertThat(violations).isNotEmpty();
    }

    @Test
    void missingTripType_shouldFailValidation() {
        SearchRequests request = new SearchRequests(
                "DEL",
                "BOM",
                LocalDate.now().plusDays(1),
                null,
                null
        );

        Set<ConstraintViolation<SearchRequests>> violations =
                validator.validate(request);

        assertThat(violations).isNotEmpty();
    }

    /* ---------------- LOMBOK COVERAGE ---------------- */

    @Test
    void testLombokMethods_equals_hashCode_toString() {
        SearchRequests r1 = new SearchRequests();
        r1.setFromPlace("DEL");

        SearchRequests r2 = new SearchRequests();
        r2.setFromPlace("DEL");

        assertThat(r1).isEqualTo(r2);
        assertThat(r1.hashCode()).isEqualTo(r2.hashCode());
        assertThat(r1.toString()).contains("DEL");
    }

    @Test
    void testReturnDateGetterSetter() {
        SearchRequests request = new SearchRequests();
        LocalDate returnDate = LocalDate.now().plusDays(5);

        request.setReturnDate(returnDate);

        assertThat(request.getReturnDate()).isEqualTo(returnDate);
    }
    
    @Test
    void testEqualsAndHashCode_allBranches() {

        SearchRequests r1 = new SearchRequests(
                "DEL", "BOM",
                LocalDate.now().plusDays(1),
                null,
                Trip.ONE_WAY
        );

        SearchRequests r2 = new SearchRequests(
                "DEL", "BOM",
                LocalDate.now().plusDays(1),
                null,
                Trip.ONE_WAY
        );

        SearchRequests r3 = new SearchRequests(
                "MUM", "DEL",
                LocalDate.now().plusDays(2),
                null,
                Trip.ROUND_TRIP
        );

        assertThat(r1.equals(r1)).isTrue();
        assertThat(r1.equals(null)).isFalse();
        assertThat(r1.equals("test")).isFalse();
        assertThat(r1.equals(r2)).isTrue();
        assertThat(r1.hashCode()).isEqualTo(r2.hashCode());
        assertThat(r1.equals(r3)).isFalse();
    }
    
    @Test
    void testEquals_nullFields_and_canEqual() {

        SearchRequests r1 = new SearchRequests();
        SearchRequests r2 = new SearchRequests();

        assertThat(r1.equals(r2)).isTrue();
        assertThat(r1.hashCode()).isEqualTo(r2.hashCode());

        assertThat(r1.canEqual(r2)).isTrue();
        assertThat(r1.canEqual("test")).isFalse();

        r1.setFromPlace("DEL");
        assertThat(r1.equals(r2)).isFalse();

        assertThat(r1.equals(null)).isFalse();
    }


}
