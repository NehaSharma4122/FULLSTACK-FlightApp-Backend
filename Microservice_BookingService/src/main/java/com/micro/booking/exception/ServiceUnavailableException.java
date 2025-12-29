package com.micro.booking.exception;


public class ServiceUnavailableException extends RuntimeException {
    public ServiceUnavailableException(String msg) {
        super(msg);
    }
}
