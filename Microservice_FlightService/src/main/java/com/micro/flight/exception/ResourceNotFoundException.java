package com.micro.flight.exception;

public class ResourceNotFoundException extends RuntimeException{
	public ResourceNotFoundException(String message) {
        super(message);
    }
}
