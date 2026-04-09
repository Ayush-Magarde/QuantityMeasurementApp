package com.apps.quantitymeasurement.service;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;

import com.apps.quantitymeasurement.dto.dtoRequest.LoginRequest;
import com.apps.quantitymeasurement.dto.dtoRequest.RegisterRequest;
import com.apps.quantitymeasurement.dto.dtoResponse.AuthResponse;
import com.apps.quantitymeasurement.dto.dto_conversion.UserDTO;
import com.apps.quantitymeasurement.entity.User;
import com.apps.quantitymeasurement.repository.UserRepository;

@Service
public class UserService {
	private UserRepository userRepository;
	private PasswordEncoder passwordEncoder;
	private JwtService jwtService;
	/*
	 * Constructor Injection
	 */
	public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtService jwtService) {
		this.userRepository = userRepository;
		this.passwordEncoder = passwordEncoder;
		this.jwtService = jwtService;
	}
	
	
	
	//register
	public AuthResponse registerUser(RegisterRequest registerRequest) {
		//step 1: validate user duplication
		User userdb = userRepository.findByEmail(registerRequest.getEmail()).orElse(null);
		if(userdb!=null) {
			throw new ResponseStatusException(HttpStatus.CONFLICT, "User already registered with this email.");
		}
		
		registerRequest.setPassword(passwordEncoder.encode(registerRequest.getPassword()));
		userRepository.save(new UserDTO().toUser(registerRequest));
		String token = jwtService.genrateToken(registerRequest.getEmail());
		return new AuthResponse(token,"User Register success");
	}
	
	
	//login
	public AuthResponse loginUser(LoginRequest loginRequest) {
		User userdb = userRepository.findByEmail(loginRequest.getEmail())
				.orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found."));
		
		if(!passwordEncoder.matches(loginRequest.getPassword(), userdb.getPassword())) {
			throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid password.");
		}
		String token = jwtService.genrateToken(loginRequest.getEmail());
		return new AuthResponse(token,"Login Success");
	}
}
