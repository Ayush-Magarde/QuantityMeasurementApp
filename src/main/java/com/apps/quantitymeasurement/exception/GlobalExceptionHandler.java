package com.apps.quantitymeasurement.exception;

import java.time.LocalDateTime;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.ErrorResponse;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import jakarta.servlet.http.HttpServletRequest;

@ControllerAdvice
public class GlobalExceptionHandler {
	
	@ExceptionHandler(RuntimeException.class)
	public ResponseEntity<ErrorResponses> handleRunTimeException(RuntimeException e, HttpServletRequest request){
		ErrorResponses errro = new ErrorResponses();
		errro.setDateTime(LocalDateTime.now());
		errro.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
		errro.setError(HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase());
		errro.setMessage(e.getMessage());
		errro.setPath(request.getRequestURL().toString());
		return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errro);
	}
	
	@ExceptionHandler(CategoryMismatchException.class)
	public ResponseEntity<ErrorResponses> handleCategoryMismatchException(CategoryMismatchException e, HttpServletRequest request){
		ErrorResponses errro = new ErrorResponses();
		errro.setDateTime(LocalDateTime.now());
		errro.setStatus(HttpStatus.BAD_REQUEST.value());
		errro.setError(HttpStatus.BAD_REQUEST.getReasonPhrase());
		errro.setMessage(e.getMessage());
		errro.setPath(request.getRequestURL().toString());
		return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errro);
	}	
	
	@ExceptionHandler(InvalidUnitException.class)
	public ResponseEntity<ErrorResponses> handleInvalidUnitException(InvalidUnitException e, HttpServletRequest request){
		ErrorResponses errro = new ErrorResponses();
		errro.setDateTime(LocalDateTime.now());
		errro.setStatus(HttpStatus.NOT_ACCEPTABLE.value());
		errro.setError(HttpStatus.NOT_ACCEPTABLE.getReasonPhrase());
		errro.setMessage(e.getMessage());
		errro.setPath(request.getRequestURL().toString());
		return ResponseEntity.status(HttpStatus.NOT_ACCEPTABLE).body(errro);
	}
	
	@ExceptionHandler(InvalidUnitMeasurementException.class)
	public ResponseEntity<ErrorResponses> handleInvalidUnitMeasurementException(InvalidUnitMeasurementException e, HttpServletRequest request){
		ErrorResponses errro = new ErrorResponses();
		errro.setDateTime(LocalDateTime.now());
		errro.setStatus(HttpStatus.NOT_ACCEPTABLE.value());
		errro.setError(HttpStatus.NOT_ACCEPTABLE.getReasonPhrase());
		errro.setMessage(e.getMessage());
		errro.setPath(request.getRequestURL().toString());
		return ResponseEntity.status(HttpStatus.NOT_ACCEPTABLE).body(errro);
	}
	
	@ExceptionHandler(QuantityMeasurementException.class)
	public ResponseEntity<ErrorResponses> handleQuantityMeasurementException(QuantityMeasurementException e, HttpServletRequest request){
		ErrorResponses errro = new ErrorResponses();
		errro.setDateTime(LocalDateTime.now());
		errro.setStatus(HttpStatus.BAD_REQUEST.value());
		errro.setError("Quantity Measurement Error");
		errro.setMessage(e.getMessage());
		errro.setPath(request.getRequestURL().toString());
		return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errro);
	}
	
	@ExceptionHandler(UnsupportedOperationException.class)
	public ResponseEntity<ErrorResponses> handleUnsupportedOperationException(UnsupportedOperationException e, HttpServletRequest request){
		ErrorResponses errro = new ErrorResponses();
		errro.setDateTime(LocalDateTime.now());
		errro.setStatus(HttpStatus.BAD_REQUEST.value());
		errro.setError("This operation not supported yet!");
		errro.setMessage(e.getMessage());
		errro.setPath(request.getRequestURL().toString());
		return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errro);
	}
	
	@ExceptionHandler(Exception.class)
	public ResponseEntity<ErrorResponses> handle(Exception e, HttpServletRequest request){
		ErrorResponses errro = new ErrorResponses();
		errro.setDateTime(LocalDateTime.now());
		errro.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
		errro.setError("Internal Server error!");
		errro.setMessage(e.getMessage());
		errro.setPath(request.getRequestURL().toString());
		return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errro);
	}
}