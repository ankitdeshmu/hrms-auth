package com.adt.authservice.model.payload;

import lombok.Data;

@Data
public class OtpRequest {
	private String username;
	private String otp;

}