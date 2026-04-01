package com.apps.quantitymeasurement.exception;

public class InvalidUnitMeasurementException extends RuntimeException{
	
	private static final long serialVersionUID = 1L;

	public InvalidUnitMeasurementException(String msg) {
		super(msg);
	}
}