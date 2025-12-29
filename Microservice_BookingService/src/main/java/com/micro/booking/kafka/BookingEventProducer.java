package com.micro.booking.kafka;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

import com.micro.booking.event.BookingEvent;

@Service
public class BookingEventProducer {
	private static final String TOPIC = "booking-events";

    @Autowired
    private KafkaTemplate<String, BookingEvent> kafkaTemplate;

    public void sendBookingEvent(BookingEvent event) {
        kafkaTemplate.send(TOPIC, event.getPnr(), event);
    }
}
