package com.apps.quantitymeasurement.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.apps.quantitymeasurement.dto.dtoResponse.AuthResponse;
import com.apps.quantitymeasurement.service.GoogleAuthService;

@RestController
@RequestMapping("/auth/google")
public class GoogleAuthController {
	
	@Autowired
	private GoogleAuthService googleAuthService;

	@GetMapping("/callback")
	public ResponseEntity<AuthResponse> handleGoogleCallback(@RequestParam String code){
		return ResponseEntity.ok(googleAuthService.handleGoogleAuth(code));
	}
}