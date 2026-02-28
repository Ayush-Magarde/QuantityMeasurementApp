package com.apps.quantitymeasurement;

public enum WeightUnit {

    KILOGRAM(1.0),
    GRAM(0.001),
    POUND(0.45359237);

    private final double conversionFactor;

    WeightUnit(double conversionFactor) {
        this.conversionFactor = conversionFactor;
    }

    // NO rounding here
    public double convertToBaseUnit(double value) {
        return value * conversionFactor;
    }

    // NO rounding here
    public double convertFromBaseUnit(double baseValue) {
        return baseValue / conversionFactor;
    }
}