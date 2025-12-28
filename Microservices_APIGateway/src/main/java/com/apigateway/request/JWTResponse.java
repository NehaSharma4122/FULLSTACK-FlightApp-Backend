package com.apigateway.request;

import com.apigateway.entity.Role;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class JWTResponse {
	private String username;
	private String email;
	private Role role;
	private String token;
}
