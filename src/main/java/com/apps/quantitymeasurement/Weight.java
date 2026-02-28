package com.apps.quantitymeasurement;

import java.util.Objects;

public class Weight {

	private static final double EPSILON = 1e-4;

    private final double value;
    private final WeightUnit unit;

    public Weight(double value, WeightUnit unit) {

        if (!Double.isFinite(value)) {
            throw new IllegalArgumentException("Value must be finite");
        }

        if (unit == null) {
            throw new IllegalArgumentException("Unit cannot be null");
        }

        this.value = value;
        this.unit = unit;
    }

    // ---------------- GETTERS ----------------

    public double getValue() {
        return value;
    }

    public WeightUnit getUnit() {
        return unit;
    }

    // ---------------- INTERNAL ----------------

    private double toBaseUnit() {
        return unit.convertToBaseUnit(value);
    }

    // ---------------- STATIC CONVERT ----------------

    public static double convert(double value, WeightUnit source, WeightUnit target) {

        if (!Double.isFinite(value)) {
            throw new IllegalArgumentException("Value must be finite");
        }

        if (source == null || target == null) {
            throw new IllegalArgumentException("Unit cannot be null");
        }

        double baseValue = source.convertToBaseUnit(value);
        return target.convertFromBaseUnit(baseValue);
    }

    // ---------------- INSTANCE CONVERT ----------------

    public Weight convertTo(WeightUnit targetUnit) {

        if (targetUnit == null) {
            throw new IllegalArgumentException("Target unit cannot be null");
        }

        double result = convert(this.value, this.unit, targetUnit);
        return new Weight(result, targetUnit);
    }

    // ---------------- ADDITION ----------------

    public Weight add(Weight other) {

        if (other == null) {
            throw new IllegalArgumentException("Weight cannot be null");
        }

        return add(other, this.unit);
    }

    public Weight add(Weight other, WeightUnit targetUnit) {

        if (other == null) {
            throw new IllegalArgumentException("Weight cannot be null");
        }

        if (targetUnit == null) {
            throw new IllegalArgumentException("Target unit cannot be null");
        }

        double base1 = this.unit.convertToBaseUnit(this.value);
        double base2 = other.unit.convertToBaseUnit(other.value);

        double sumBase = base1 + base2;

        double resultValue = targetUnit.convertFromBaseUnit(sumBase);

        return new Weight(resultValue, targetUnit);
    }

    // static add (used in tests)
    public static Weight add(Weight w1, Weight w2, WeightUnit targetUnit) {

        if (w1 == null || w2 == null)
            throw new IllegalArgumentException("Weight cannot be null");

        return w1.add(w2, targetUnit);
    }

    // ---------------- EQUALS ----------------

    @Override
    public boolean equals(Object obj) {

        if (this == obj)
            return true;

        if (!(obj instanceof Weight))
            return false;

        Weight other = (Weight) obj;

        double base1 = this.toBaseUnit();
        double base2 = other.toBaseUnit();

        return Math.abs(base1 - base2) <= EPSILON;
    }

    @Override
    public int hashCode() {
        long normalized = Math.round(toBaseUnit() / EPSILON);
        return Objects.hash(normalized);
    }

    @Override
    public String toString() {
        return String.format("%.4f %s", value, unit);
    }
}