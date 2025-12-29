package com.micro.booking.repository;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.data.mongo.DataMongoTest;

import com.micro.booking.entity.Ticket;

import reactor.test.StepVerifier;

@DataMongoTest
class TicketRepositoryTest {

    @Autowired
    private TicketRepository ticketRepository;

    @Test
    void repositoryMethods_shouldExist() {
        StepVerifier.create(ticketRepository.findByCustomerEmail("x@y.com"))
                .verifyComplete();

        StepVerifier.create(ticketRepository.findByPnr("PNR"))
                .verifyComplete();
    }
}
