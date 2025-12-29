package com.micro.booking.kafka;

import static org.mockito.Mockito.verify;

import java.time.LocalDateTime;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.kafka.core.KafkaTemplate;

import com.micro.booking.event.BookingEvent;

class BookingEventProducerTest {

    @Mock
    private KafkaTemplate<String, BookingEvent> kafkaTemplate;

    @InjectMocks
    private BookingEventProducer producer;

    @BeforeEach
    void setup() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void sendBookingEvent_shouldPublishToKafka() {
        BookingEvent event = new BookingEvent(
                "BOOKED",
                "PNR789",
                "test@mail.com",
                "FL1",
                3,
                LocalDateTime.now()
        );

        producer.sendBookingEvent(event);

        verify(kafkaTemplate).send("booking-events", "PNR789", event);
    }
}
