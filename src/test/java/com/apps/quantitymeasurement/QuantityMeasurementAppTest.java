package com.apps.quantitymeasurement;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class QuantityMeasurementAppTest {

    @Test
    public void testEquality_YardToYard_SameValue() {
        Length yard1 = new Length(1.0, LengthUnit.YARDS);
        Length yard2 = new Length(1.0, LengthUnit.YARDS);
        assertEquals(yard1, yard2);
    }

    @Test
    public void testEquality_YardToYard_DifferentValue() {
        Length yard1 = new Length(1.0, LengthUnit.YARDS);
        Length yard2 = new Length(2.0, LengthUnit.YARDS);
        assertNotEquals(yard1, yard2);
    }

    @Test
    public void testEquality_YardToFeet_EquivalentValue() {
        Length yard1 = new Length(1.0, LengthUnit.YARDS);
        Length feet3 = new Length(3.0, LengthUnit.FEET);
        assertEquals(yard1, feet3);
    }

    @Test
    public void testEquality_FeetToYard_EquivalentValue() {
        Length feet3 = new Length(3.0, LengthUnit.FEET);
        Length yard1 = new Length(1.0, LengthUnit.YARDS);
        assertEquals(feet3, yard1);
    }

    @Test
    public void testEquality_YardToInches_EquivalentValue() {
        Length yard1 = new Length(1.0, LengthUnit.YARDS);
        Length inch36 = new Length(36.0, LengthUnit.INCHES);
        assertEquals(yard1, inch36);
    }

    @Test
    public void testEquality_InchesToYard_EquivalentValue() {
        Length inch36 = new Length(36.0, LengthUnit.INCHES);
        Length yard1 = new Length(1.0, LengthUnit.YARDS);
        assertEquals(inch36, yard1);
    }

    @Test
    public void testEquality_YardToFeet_NonEquivalentValue() {
        Length yard1 = new Length(1.0, LengthUnit.YARDS);
        Length feet2 = new Length(2.0, LengthUnit.FEET);
        assertNotEquals(yard1, feet2);
    }

    @Test
    public void testEquality_CentimetersToInches_EquivalentValue() {
        Length cm1 = new Length(1.0, LengthUnit.CENTIMETERS);
        Length inchValue = new Length(0.393701, LengthUnit.INCHES);
        assertEquals(cm1, inchValue);
    }

    @Test
    public void testEquality_CentimetersToFeet_NonEquivalentValue() {
        Length cm1 = new Length(1.0, LengthUnit.CENTIMETERS);
        Length feet1 = new Length(1.0, LengthUnit.FEET);
        assertNotEquals(cm1, feet1);
    }

    @Test
    public void testEquality_MultiUnit_TransitiveProperty() {
        Length yard = new Length(1.0, LengthUnit.YARDS);
        Length feet = new Length(3.0, LengthUnit.FEET);
        Length inches = new Length(36.0, LengthUnit.INCHES);
        assertEquals(yard, feet);
        assertEquals(feet, inches);
        assertEquals(yard, inches);
    }

    @Test
    public void testEquality_NullUnit() {
        assertThrows(IllegalArgumentException.class,
                () -> new Length(1.0, null));
    }

    @Test
    public void testEquality_YardSameReference() {
        Length yard = new Length(2.0, LengthUnit.YARDS);
        assertEquals(yard, yard);
    }

    @Test
    public void testEquality_YardNullComparison() {
        Length yard = new Length(2.0, LengthUnit.YARDS);
        assertNotEquals(yard, null);
    }

    @Test
    public void testEquality_CentimetersSameReference() {
        Length cm = new Length(2.0, LengthUnit.CENTIMETERS);
        assertEquals(cm, cm);
    }

    @Test
    public void testEquality_CentimetersNullComparison() {
        Length cm = new Length(2.0, LengthUnit.CENTIMETERS);
        assertNotEquals(cm, null);
    }

    @Test
    public void testEquality_AllUnits_ComplexScenario() {
        Length yards = new Length(2.0, LengthUnit.YARDS);
        Length feet = new Length(6.0, LengthUnit.FEET);
        Length inches = new Length(72.0, LengthUnit.INCHES);
        assertEquals(yards, feet);
        assertEquals(feet, inches);
        assertEquals(yards, inches);
    }

    @Test
    public void testEquality_CentimetersToCentimeters_SameValue() {
        Length cm2a = new Length(2.0, LengthUnit.CENTIMETERS);
        Length cm2b = new Length(2.0, LengthUnit.CENTIMETERS);
        assertEquals(cm2a, cm2b);
    }

    @Test
    public void testEquality_CentimetersToCentimeters_DifferentValue() {
        Length cm2 = new Length(2.0, LengthUnit.CENTIMETERS);
        Length cm3 = new Length(3.0, LengthUnit.CENTIMETERS);
        assertNotEquals(cm2, cm3);
    }

    @Test
    public void testEquality_InchesToCentimeters_EquivalentValue() {
        Length inchValue = new Length(0.393701, LengthUnit.INCHES);
        Length cm1 = new Length(1.0, LengthUnit.CENTIMETERS);
        assertEquals(inchValue, cm1);
    }

    @Test
    public void testEquality_DifferentClass() {
        Length yard = new Length(2.0, LengthUnit.YARDS);
        assertFalse(yard.equals("2.0"));
    }

    @Test
    public void testEquality_NaN() {
        assertThrows(IllegalArgumentException.class,
                () -> new Length(Double.NaN, LengthUnit.FEET));
    }

    @Test
    public void testEquality_Infinity() {
        assertThrows(IllegalArgumentException.class,
                () -> new Length(Double.POSITIVE_INFINITY, LengthUnit.CENTIMETERS));
    }

    @Test
    public void testEquality_DemonstrateLengthComparisonMethod() {
        boolean result = QuantityMeasurementApp.demonstrateLengthComparison(
                1.0, LengthUnit.YARDS,
                36.0, LengthUnit.INCHES
        );
        assertTrue(result);
    }

    @Test
    public void testConversion_FeetToInches() {
        Length result = QuantityMeasurementApp.demonstrateLengthConversion(1.0, LengthUnit.FEET, LengthUnit.INCHES);
        assertEquals(new Length(12.0, LengthUnit.INCHES), result);
    }

    @Test
    public void testConversion_InchesToFeet() {
        Length result = QuantityMeasurementApp.demonstrateLengthConversion(24.0, LengthUnit.INCHES, LengthUnit.FEET);
        assertEquals(new Length(2.0, LengthUnit.FEET), result);
    }

    @Test
    public void testConversion_YardsToInches() {
        Length result = QuantityMeasurementApp.demonstrateLengthConversion(1.0, LengthUnit.YARDS, LengthUnit.INCHES);
        assertEquals(new Length(36.0, LengthUnit.INCHES), result);
    }

    @Test
    public void testConversion_InchesToYards() {
        Length result = QuantityMeasurementApp.demonstrateLengthConversion(72.0, LengthUnit.INCHES, LengthUnit.YARDS);
        assertEquals(new Length(2.0, LengthUnit.YARDS), result);
    }

    @Test
    public void testConversion_CentimetersToInches() {
        Length result = QuantityMeasurementApp.demonstrateLengthConversion(2.54, LengthUnit.CENTIMETERS, LengthUnit.INCHES);
        assertTrue(result.equals(new Length(1.0, LengthUnit.INCHES)));
    }

    @Test
    public void testConversion_FeetToYards() {
        Length result = QuantityMeasurementApp.demonstrateLengthConversion(6.0, LengthUnit.FEET, LengthUnit.YARDS);
        assertEquals(new Length(2.0, LengthUnit.YARDS), result);
    }

    @Test
    public void testConversion_RoundTrip_PreservesValue() {
        Length original = new Length(3.0, LengthUnit.FEET);
        Length converted = original.convertTo(LengthUnit.INCHES).convertTo(LengthUnit.FEET);
        assertTrue(original.equals(converted));
    }

    @Test
    public void testConversion_ZeroValue() {
        Length result = QuantityMeasurementApp.demonstrateLengthConversion(0.0, LengthUnit.FEET, LengthUnit.INCHES);
        assertEquals(new Length(0.0, LengthUnit.INCHES), result);
    }

    @Test
    public void testConversion_NegativeValue() {
        Length result = QuantityMeasurementApp.demonstrateLengthConversion(-1.0, LengthUnit.FEET, LengthUnit.INCHES);
        assertEquals(new Length(-12.0, LengthUnit.INCHES), result);
    }

    @Test
    public void testConversion_InvalidUnit_Throws() {
        assertThrows(IllegalArgumentException.class,
                () -> QuantityMeasurementApp.demonstrateLengthConversion(1.0, null, LengthUnit.INCHES));
    }

    @Test
    public void testConversion_PrecisionTolerance() {
        double result = Length.convert(30.48, LengthUnit.CENTIMETERS, LengthUnit.FEET);
        assertTrue(Math.abs(result - 1.0) < 1e-6);
    }

    @Test
    public void testConversion_SameUnit() {
        Length result = QuantityMeasurementApp.demonstrateLengthConversion(5.0, LengthUnit.FEET, LengthUnit.FEET);
        assertEquals(new Length(5.0, LengthUnit.FEET), result);
    }

    @Test
    public void testAddition_SameUnit_FeetPlusFeet() {
        Length result = QuantityMeasurementApp.demonstrateLengthAddition(
                new Length(1.0, LengthUnit.FEET),
                new Length(2.0, LengthUnit.FEET)
        );
        assertEquals(new Length(3.0, LengthUnit.FEET), result);
    }

    @Test
    public void testAddition_SameUnit_InchPlusInch() {
        Length result = QuantityMeasurementApp.demonstrateLengthAddition(
                new Length(6.0, LengthUnit.INCHES),
                new Length(6.0, LengthUnit.INCHES)
        );
        assertEquals(new Length(12.0, LengthUnit.INCHES), result);
    }

    @Test
    public void testAddition_CrossUnit_FeetPlusInches() {
        Length result = QuantityMeasurementApp.demonstrateLengthAddition(
                new Length(1.0, LengthUnit.FEET),
                new Length(12.0, LengthUnit.INCHES)
        );
        assertEquals(new Length(2.0, LengthUnit.FEET), result);
    }

    @Test
    public void testAddition_CrossUnit_InchPlusFeet() {
        Length result = QuantityMeasurementApp.demonstrateLengthAddition(
                new Length(12.0, LengthUnit.INCHES),
                new Length(1.0, LengthUnit.FEET)
        );
        assertEquals(new Length(24.0, LengthUnit.INCHES), result);
    }

    @Test
    public void testAddition_CrossUnit_YardPlusFeet() {
        Length result = QuantityMeasurementApp.demonstrateLengthAddition(
                new Length(1.0, LengthUnit.YARDS),
                new Length(3.0, LengthUnit.FEET)
        );
        assertEquals(new Length(2.0, LengthUnit.YARDS), result);
    }

    @Test
    public void testAddition_CrossUnit_CentimeterPlusInch() {
        Length result = QuantityMeasurementApp.demonstrateLengthAddition(
                new Length(2.54, LengthUnit.CENTIMETERS),
                new Length(1.0, LengthUnit.INCHES)
        );
        assertTrue(result.equals(new Length(5.08, LengthUnit.CENTIMETERS)));
    }

    @Test
    public void testAddition_Commutativity() {
        Length a = new Length(1.0, LengthUnit.FEET);
        Length b = new Length(12.0, LengthUnit.INCHES);
        assertEquals(a.add(b), b.add(a).convertTo(LengthUnit.FEET));
    }

    @Test
    public void testAddition_WithZero() {
        Length result = QuantityMeasurementApp.demonstrateLengthAddition(
                new Length(5.0, LengthUnit.FEET),
                new Length(0.0, LengthUnit.INCHES)
        );
        assertEquals(new Length(5.0, LengthUnit.FEET), result);
    }

    @Test
    public void testAddition_NegativeValues() {
        Length result = QuantityMeasurementApp.demonstrateLengthAddition(
                new Length(5.0, LengthUnit.FEET),
                new Length(-2.0, LengthUnit.FEET)
        );
        assertEquals(new Length(3.0, LengthUnit.FEET), result);
    }

    @Test
    public void testAddition_NullSecondOperand() {
        assertThrows(IllegalArgumentException.class,
                () -> QuantityMeasurementApp.demonstrateLengthAddition(
                        new Length(1.0, LengthUnit.FEET), null));
    }
}