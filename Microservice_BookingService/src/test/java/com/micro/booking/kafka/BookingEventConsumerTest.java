package com.micro.booking.kafka;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;

import java.time.LocalDateTime;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;

import com.micro.booking.event.BookingEvent;

class BookingEventConsumerTest {

    @Mock
    private JavaMailSender mailSender;

    @InjectMocks
    private BookingEventConsumer consumer;

    @BeforeEach
    void setup() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void consume_shouldSendBookingConfirmationMail() {
        BookingEvent event = new BookingEvent(
                "BOOKED",
                "PNR123",
                "test@mail.com",
                "FL1",
                2,
                LocalDateTime.now()
        );

        consumer.consume(event);

        verify(mailSender).send(any(SimpleMailMessage.class));
    }

    @Test
    void consume_shouldSendCancellationMail() {
        BookingEvent event = new BookingEvent(
                "CANCELLED",
                "PNR456",
                "test@mail.com",
                "FL1",
                1,
                LocalDateTime.now()
        );

        consumer.consume(event);

        verify(mailSender).send(any(SimpleMailMessage.class));
    }
}
