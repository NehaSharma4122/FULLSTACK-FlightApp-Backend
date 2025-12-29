package com.micro.booking.kafka;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import com.micro.booking.event.BookingEvent;

@Service
public class BookingEventConsumer {

    @Autowired
    private JavaMailSender mailSender;

    @KafkaListener(topics = "booking-events", groupId = "booking-email-group")
    public void consume(BookingEvent event) {

        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(event.getEmail());

        if ("BOOKED".equals(event.getType())) {
            message.setSubject("Flight Booking Confirmed");
            message.setText(
                "Your booking is confirmed.\nPNR: " + event.getPnr()
            );
        } else {
            message.setSubject("Flight Booking Cancelled");
            message.setText(
                "Your booking has been cancelled.\nPNR: " + event.getPnr()
            );
        }

        mailSender.send(message);
    }
}

