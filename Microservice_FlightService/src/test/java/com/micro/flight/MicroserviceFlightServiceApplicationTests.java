package com.micro.flight;

import static org.assertj.core.api.Assertions.assertThatCode;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class MicroserviceFlightServiceApplicationTests {
	@Test
    void mainMethod_shouldStartApplication() {
        assertThatCode(() ->
                MicroserviceFlightServiceApplication.main(
                        new String[] {}
                )
        ).doesNotThrowAnyException();
    }
	@Test
	void contextLoads() {
	}

}
