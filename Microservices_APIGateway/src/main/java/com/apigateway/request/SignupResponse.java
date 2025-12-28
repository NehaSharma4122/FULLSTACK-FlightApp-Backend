package com.apigateway.request;

import com.apigateway.entity.Role;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class SignupResponse {
	@NotBlank
	private String username;

	@Email
	@NotBlank
	private String email;
	
	private String encryptedPassword;
	private Role role;
	
}