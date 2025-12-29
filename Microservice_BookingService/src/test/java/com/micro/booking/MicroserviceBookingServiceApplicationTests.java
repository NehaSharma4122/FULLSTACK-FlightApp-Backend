package com.micro.booking;

import static org.assertj.core.api.Assertions.assertThatCode;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class MicroserviceBookingServiceApplicationTests {

	@Test
    void mainMethod_shouldStartApplication() {
        assertThatCode(() ->
                MicroserviceBookingServiceApplication.main(new String[]{})
        ).doesNotThrowAnyException();
    }

}
