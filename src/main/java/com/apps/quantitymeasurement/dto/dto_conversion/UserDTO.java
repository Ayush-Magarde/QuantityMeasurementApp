package com.apps.quantitymeasurement.dto.dto_conversion;

import com.apps.quantitymeasurement.dto.dtoRequest.RegisterRequest;
import com.apps.quantitymeasurement.entity.User;

public class UserDTO {
	public User toUser(RegisterRequest registerRequest){
		return new User(registerRequest.getUsername(), registerRequest.getEmail(), registerRequest.getPassword(), registerRequest.getRole());
	}
}