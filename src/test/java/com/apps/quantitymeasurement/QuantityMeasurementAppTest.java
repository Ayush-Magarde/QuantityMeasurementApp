package com.apps.quantitymeasurement;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class QuantityMeasurementAppTest {


    // Equality Tests
	
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
        assertEquals(
                new Length(1.0, LengthUnit.YARDS),
                new Length(3.0, LengthUnit.FEET)
        );
    }

    @Test
    public void testEquality_YardToInches_EquivalentValue() {
        assertEquals(
                new Length(1.0, LengthUnit.YARDS),
                new Length(36.0, LengthUnit.INCHES)
        );
    }

    @Test
    public void testEquality_YardToFeet_NonEquivalentValue() {
        assertNotEquals(
                new Length(1.0, LengthUnit.YARDS),
                new Length(2.0, LengthUnit.FEET)
        );
    }

    @Test
    public void testEquality_CentimetersToInches_EquivalentValue() {
        assertEquals(
                new Length(1.0, LengthUnit.CENTIMETERS),
                new Length(0.393701, LengthUnit.INCHES)
        );
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
    public void testEquality_NaN() {
        assertThrows(IllegalArgumentException.class,
                () -> new Length(Double.NaN, LengthUnit.FEET));
    }

    @Test
    public void testEquality_Infinity() {
        assertThrows(IllegalArgumentException.class,
                () -> new Length(Double.POSITIVE_INFINITY, LengthUnit.FEET));
    }

    @Test
    public void testEquality_NullComparison() {
        Length yard = new Length(2.0, LengthUnit.YARDS);
        assertNotEquals(yard, null);
    }

    @Test
    public void testEquality_DifferentClass() {
        Length yard = new Length(2.0, LengthUnit.YARDS);
        assertFalse(yard.equals("2.0"));
    }

    
    
    // Conversion Tests

    @Test
    public void testConversion_FeetToInches() {
        Length result = new Length(1.0, LengthUnit.FEET).convertTo(LengthUnit.INCHES);
        assertEquals(new Length(12.0, LengthUnit.INCHES), result);
    }

    @Test
    public void testConversion_InchesToFeet() {
        Length result = new Length(24.0, LengthUnit.INCHES).convertTo(LengthUnit.FEET);
        assertEquals(new Length(2.0, LengthUnit.FEET), result);
    }

    @Test
    public void testConversion_YardsToInches() {
        Length result = new Length(1.0, LengthUnit.YARDS).convertTo(LengthUnit.INCHES);
        assertEquals(new Length(36.0, LengthUnit.INCHES), result);
    }

    @Test
    public void testConversion_InchesToYards() {
        Length result = new Length(72.0, LengthUnit.INCHES).convertTo(LengthUnit.YARDS);
        assertEquals(new Length(2.0, LengthUnit.YARDS), result);
    }

    @Test
    public void testConversion_CentimetersToInches() {
        Length result = new Length(2.54, LengthUnit.CENTIMETERS).convertTo(LengthUnit.INCHES);
        assertEquals(new Length(1.0, LengthUnit.INCHES), result);
    }

    @Test
    public void testConversion_FeetToYards() {
        Length result = new Length(6.0, LengthUnit.FEET).convertTo(LengthUnit.YARDS);
        assertEquals(new Length(2.0, LengthUnit.YARDS), result);
    }

    @Test
    public void testConversion_RoundTrip_PreservesValue() {
        Length original = new Length(3.0, LengthUnit.FEET);
        Length converted = original.convertTo(LengthUnit.INCHES).convertTo(LengthUnit.FEET);
        assertEquals(original, converted);
    }

    @Test
    public void testConversion_ZeroValue() {
        Length result = new Length(0.0, LengthUnit.FEET).convertTo(LengthUnit.INCHES);
        assertEquals(new Length(0.0, LengthUnit.INCHES), result);
    }

    @Test
    public void testConversion_NegativeValue() {
        Length result = new Length(-1.0, LengthUnit.FEET).convertTo(LengthUnit.INCHES);
        assertEquals(new Length(-12.0, LengthUnit.INCHES), result);
    }

    @Test
    public void testConversion_InvalidUnit_Throws() {
        assertThrows(IllegalArgumentException.class,
                () -> new Length(1.0, LengthUnit.FEET).convertTo(null));
    }

    @Test
    public void testConversion_PrecisionTolerance() {
        double result = Length.convert(30.48, LengthUnit.CENTIMETERS, LengthUnit.FEET);
        assertTrue(Math.abs(result - 1.0) < 1e-2);
    }

    @Test
    public void testConversion_SameUnit() {
        Length result = new Length(5.0, LengthUnit.FEET).convertTo(LengthUnit.FEET);
        assertEquals(new Length(5.0, LengthUnit.FEET), result);
    }

    
    
    // Addition Tests

    @Test
    public void testAddition_SameUnit_FeetPlusFeet() {
        Length result = new Length(1.0, LengthUnit.FEET)
                .add(new Length(2.0, LengthUnit.FEET));
        assertEquals(new Length(3.0, LengthUnit.FEET), result);
    }

    @Test
    public void testAddition_SameUnit_InchPlusInch() {
        Length result = new Length(6.0, LengthUnit.INCHES)
                .add(new Length(6.0, LengthUnit.INCHES));
        assertEquals(new Length(12.0, LengthUnit.INCHES), result);
    }

    @Test
    public void testAddition_CrossUnit_FeetPlusInches() {
        Length result = new Length(1.0, LengthUnit.FEET)
                .add(new Length(12.0, LengthUnit.INCHES));
        assertEquals(new Length(2.0, LengthUnit.FEET), result);
    }

    @Test
    public void testAddition_CrossUnit_InchPlusFeet() {
        Length result = new Length(12.0, LengthUnit.INCHES)
                .add(new Length(1.0, LengthUnit.FEET));
        assertEquals(new Length(24.0, LengthUnit.INCHES), result);
    }

    @Test
    public void testAddition_CrossUnit_YardPlusFeet() {
        Length result = new Length(1.0, LengthUnit.YARDS)
                .add(new Length(3.0, LengthUnit.FEET));
        assertEquals(new Length(2.0, LengthUnit.YARDS), result);
    }

    @Test
    public void testAddition_CrossUnit_CentimeterPlusInch() {
        Length result = new Length(2.54, LengthUnit.CENTIMETERS)
                .add(new Length(1.0, LengthUnit.INCHES));
        assertEquals(new Length(5.08, LengthUnit.CENTIMETERS), result);
    }

    @Test
    public void testAddition_Commutativity() {
        Length a = new Length(1.0, LengthUnit.FEET);
        Length b = new Length(12.0, LengthUnit.INCHES);

        assertEquals(a.add(b), b.add(a).convertTo(LengthUnit.FEET));
    }

    @Test
    public void testAddition_WithZero() {
        Length result = new Length(5.0, LengthUnit.FEET)
                .add(new Length(0.0, LengthUnit.INCHES));
        assertEquals(new Length(5.0, LengthUnit.FEET), result);
    }

    @Test
    public void testAddition_NegativeValues() {
        Length result = new Length(5.0, LengthUnit.FEET)
                .add(new Length(-2.0, LengthUnit.FEET));
        assertEquals(new Length(3.0, LengthUnit.FEET), result);
    }

    @Test
    public void testAddition_NullSecondOperand() {
        assertThrows(IllegalArgumentException.class,
                () -> new Length(1.0, LengthUnit.FEET).add(null));
    }

    @Test
    public void testAddition_LargeValues() {
        Length result = new Length(1e6, LengthUnit.FEET)
                .add(new Length(1e6, LengthUnit.FEET));
        assertEquals(new Length(2e6, LengthUnit.FEET), result);
    }

    @Test
    public void testAddition_SmallValues() {
        Length result = new Length(0.001, LengthUnit.FEET)
                .add(new Length(0.002, LengthUnit.FEET));
        assertEquals(new Length(0.003, LengthUnit.FEET), result);
    }
}