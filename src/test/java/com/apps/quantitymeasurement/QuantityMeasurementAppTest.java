
package com.apps.quantitymeasurement;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class QuantityMeasurementAppTest {

    @Test
    public void testEquality_YardToYard_SameValue() {
        assertTrue(new Length(1.0, Length.LengthUnit.YARDS).equals(new Length(1.0, Length.LengthUnit.YARDS)));
    }

    @Test
    public void testEquality_YardToFeet_EquivalentValue() {
        assertTrue(new Length(1.0, Length.LengthUnit.YARDS).equals(new Length(3.0, Length.LengthUnit.FEET)));
    }

    @Test
    public void testEquality_YardToInches_EquivalentValue() {
        assertTrue(new Length(1.0, Length.LengthUnit.YARDS).equals(new Length(36.0, Length.LengthUnit.INCHES)));
    }

    @Test
    public void testEquality_CentimetersToInches_EquivalentValue() {
        assertTrue(
                new Length(1.0, Length.LengthUnit.CENTIMETERS).equals(new Length(0.393701, Length.LengthUnit.INCHES)));
    }

    @Test
    public void testEquality_YardToFeet_NonEquivalentValue() {
        assertFalse(new Length(1.0, Length.LengthUnit.YARDS).equals(new Length(2.0, Length.LengthUnit.FEET)));
    }

    @Test
    public void testEquality_CentimetersToFeet_NonEquivalentValue() {
        assertFalse(new Length(1.0, Length.LengthUnit.CENTIMETERS).equals(new Length(1.0, Length.LengthUnit.FEET)));
    }

    @Test
    public void testEquality_MultiUnit_TransitiveProperty() {
        Length yard = new Length(1.0, Length.LengthUnit.YARDS);
        Length feet = new Length(3.0, Length.LengthUnit.FEET);
        Length inches = new Length(36.0, Length.LengthUnit.INCHES);

        assertTrue(yard.equals(feet));
        assertTrue(feet.equals(inches));
        assertTrue(yard.equals(inches));
    }

    @Test
    public void testEquality_SameReference() {
        Length length = new Length(2.0, Length.LengthUnit.YARDS);
        assertTrue(length.equals(length));
    }

    @Test
    public void testEquality_NullComparison() {
        Length length = new Length(2.0, Length.LengthUnit.YARDS);
        assertFalse(length.equals(null));
    }

    @Test
    public void testEquality_NullUnit() {
        assertThrows(IllegalArgumentException.class, () -> new Length(1.0, null));
    }

    @Test
    public void testConversion_FeetToInches() {
        double result = Length.convert(1.0, Length.LengthUnit.FEET, Length.LengthUnit.INCHES);
        assertEquals(12.0, result);
    }

    @Test
    public void testConversion_InchesToFeet() {
        double result = Length.convert(24.0, Length.LengthUnit.INCHES, Length.LengthUnit.FEET);
        assertEquals(2.0, result);
    }

    @Test
    public void testConversion_YardsToInches() {
        double result = Length.convert(1.0, Length.LengthUnit.YARDS, Length.LengthUnit.INCHES);
        assertEquals(36.0, result);
    }

    @Test
    public void testConversion_CentimetersToInches() {
        double result = Length.convert(2.54, Length.LengthUnit.CENTIMETERS, Length.LengthUnit.INCHES);
        assertEquals(1.0, result, 1e-6);
    }

    @Test
    public void testConversion_ZeroValue() {
        double result = Length.convert(0.0, Length.LengthUnit.FEET, Length.LengthUnit.INCHES);
        assertEquals(0.0, result);
    }

    @Test
    public void testConversion_NegativeValue() {
        double result = Length.convert(-1.0, Length.LengthUnit.FEET, Length.LengthUnit.INCHES);
        assertEquals(-12.0, result);
    }

    @Test
    public void testConversion_SameUnit() {
        double result = Length.convert(5.0, Length.LengthUnit.FEET, Length.LengthUnit.FEET);
        assertEquals(5.0, result);
    }

    @Test
    public void testConversion_NullUnit() {
        assertThrows(IllegalArgumentException.class, () -> Length.convert(1.0, null, Length.LengthUnit.FEET));
    }

    @Test
    public void testConversion_NaN() {
        assertThrows(IllegalArgumentException.class,
                () -> Length.convert(Double.NaN, Length.LengthUnit.FEET, Length.LengthUnit.INCHES));
    }

    @Test
    public void testConversion_Infinite() {
        assertThrows(IllegalArgumentException.class,
                () -> Length.convert(Double.POSITIVE_INFINITY, Length.LengthUnit.FEET, Length.LengthUnit.INCHES));
    }

    @Test
    public void testAddition_SameUnit_FeetPlusFeet() {

        Length l1 = new Length(1.0, Length.LengthUnit.FEET);
        Length l2 = new Length(2.0, Length.LengthUnit.FEET);

        Length result = l1.add(l2);

        assertEquals(new Length(3.0, Length.LengthUnit.FEET), result);
    }

    @Test
    public void testAddition_SameUnit_InchPlusInch() {

        Length l1 = new Length(6.0, Length.LengthUnit.INCHES);
        Length l2 = new Length(6.0, Length.LengthUnit.INCHES);

        Length result = l1.add(l2);

        assertEquals(new Length(12.0, Length.LengthUnit.INCHES), result);
    }

    @Test
    public void testAddition_CrossUnit_FeetPlusInches() {

        Length l1 = new Length(1.0, Length.LengthUnit.FEET);
        Length l2 = new Length(12.0, Length.LengthUnit.INCHES);

        Length result = l1.add(l2);

        assertEquals(new Length(2.0, Length.LengthUnit.FEET), result);
    }

    @Test
    public void testAddition_CrossUnit_InchPlusFeet() {

        Length l1 = new Length(12.0, Length.LengthUnit.INCHES);
        Length l2 = new Length(1.0, Length.LengthUnit.FEET);

        Length result = l1.add(l2);

        assertEquals(new Length(24.0, Length.LengthUnit.INCHES), result);
    }

    @Test
    public void testAddition_CrossUnit_YardPlusFeet() {

        Length l1 = new Length(1.0, Length.LengthUnit.YARDS);
        Length l2 = new Length(3.0, Length.LengthUnit.FEET);

        Length result = l1.add(l2);

        assertEquals(new Length(2.0, Length.LengthUnit.YARDS), result);
    }

    @Test
    public void testAddition_CrossUnit_CentimeterPlusInch() {

        Length l1 = new Length(2.54, Length.LengthUnit.CENTIMETERS);
        Length l2 = new Length(1.0, Length.LengthUnit.INCHES);

        Length result = l1.add(l2);

        assertTrue(result.equals(new Length(5.08, Length.LengthUnit.CENTIMETERS)));
    }

    @Test
    public void testAddition_Commutativity() {

        Length l1 = new Length(1.0, Length.LengthUnit.FEET);
        Length l2 = new Length(12.0, Length.LengthUnit.INCHES);

        assertTrue(l1.add(l2).equals(l2.add(l1)));
    }

    @Test
    public void testAddition_WithZero() {

        Length l1 = new Length(5.0, Length.LengthUnit.FEET);
        Length l2 = new Length(0.0, Length.LengthUnit.INCHES);

        Length result = l1.add(l2);

        assertEquals(new Length(5.0, Length.LengthUnit.FEET), result);
    }

    @Test
    public void testAddition_NegativeValues() {

        Length l1 = new Length(5.0, Length.LengthUnit.FEET);
        Length l2 = new Length(-2.0, Length.LengthUnit.FEET);

        Length result = l1.add(l2);

        assertEquals(new Length(3.0, Length.LengthUnit.FEET), result);
    }

    @Test
    public void testAddition_NullSecondOperand() {

        Length l1 = new Length(1.0, Length.LengthUnit.FEET);

        assertThrows(IllegalArgumentException.class, () -> l1.add(null));
    }

    @Test
    public void testAddition_LargeValues() {

        Length l1 = new Length(1e6, Length.LengthUnit.FEET);
        Length l2 = new Length(1e6, Length.LengthUnit.FEET);

        Length result = l1.add(l2);

        assertEquals(new Length(2e6, Length.LengthUnit.FEET), result);
    }

    @Test
    public void testAddition_SmallValues() {

        Length l1 = new Length(0.01, Length.LengthUnit.FEET);
        Length l2 = new Length(0.02, Length.LengthUnit.FEET);

        Length result = l1.add(l2);

        assertEquals(new Length(0.03, Length.LengthUnit.FEET), result);
    }
    
    //-------------------------------------------------------------------
	  
    private static final double EPSILON = 1e-5;
    // ---------------- Weight Equality Tests ----------------
	
	 @Test
	 public void testWeightEquality_KilogramToKilogram_SameValue() {
	     assertTrue(new Weight(1.0, WeightUnit.KILOGRAM)
	             .equals(new Weight(1.0, WeightUnit.KILOGRAM)));
	 }
	
	 @Test
	 public void testWeightEquality_KilogramToGram_EquivalentValue() {
	     assertTrue(new Weight(1.0, WeightUnit.KILOGRAM)
	             .equals(new Weight(1000.0, WeightUnit.GRAM)));
	 }
	
	 @Test
	 public void testWeightEquality_KilogramToPound_EquivalentValue() {
	     assertTrue(new Weight(1.0, WeightUnit.KILOGRAM)
	             .equals(new Weight(2.20462, WeightUnit.POUND)));
	 }
	
	 @Test
	 public void testWeightEquality_ZeroValue() {
	     assertTrue(new Weight(0.0, WeightUnit.KILOGRAM)
	             .equals(new Weight(0.0, WeightUnit.GRAM)));
	 }
	
	 @Test
	 public void testWeightEquality_NegativeValue() {
	     assertTrue(new Weight(-1.0, WeightUnit.KILOGRAM)
	             .equals(new Weight(-1000.0, WeightUnit.GRAM)));
	 }
	
	 @Test
	 public void testWeightEquality_SameReference() {
	     Weight w = new Weight(5.0, WeightUnit.KILOGRAM);
	     assertTrue(w.equals(w));
	 }
	
	 @Test
	 public void testWeightEquality_NullComparison() {
	     assertFalse(new Weight(1.0, WeightUnit.KILOGRAM).equals(null));
	 }
	
	 @Test
	 public void testWeightVsLength_Incompatible() {
	     assertFalse(new Weight(1.0, WeightUnit.KILOGRAM)
	             .equals(new Length(1.0, Length.LengthUnit.FEET)));
	 }
	
	 // ---------------- Weight Conversion Tests ----------------
	
	 @Test
	 public void testWeightConversion_KgToGram() {
	     Weight result = new Weight(1.0, WeightUnit.KILOGRAM)
	             .convertTo(WeightUnit.GRAM);
	
	     assertEquals(1000.0, result.getValue(), EPSILON);
	 }
	
	 @Test
	 public void testWeightConversion_KgToPound() {
	     Weight result = new Weight(1.0, WeightUnit.KILOGRAM)
	             .convertTo(WeightUnit.POUND);
	
	     assertEquals(2.20462, result.getValue(), 1e-4);
	 }
	
	 @Test
	 public void testWeightConversion_PoundToKg() {
	     Weight result = new Weight(2.20462, WeightUnit.POUND)
	             .convertTo(WeightUnit.KILOGRAM);
	
	     assertEquals(1.0, result.getValue(), 1e-4);
	 }
	
	 @Test
	 public void testWeightConversion_RoundTrip() {
	     Weight original = new Weight(2.5, WeightUnit.KILOGRAM);
	
	     Weight converted = original
	             .convertTo(WeightUnit.GRAM)
	             .convertTo(WeightUnit.KILOGRAM);
	
	     assertEquals(2.5, converted.getValue(), EPSILON);
	 }
	
	 @Test
	 public void testWeightConversion_InvalidUnit() {
	     assertThrows(IllegalArgumentException.class,
	             () -> new Weight(1.0, null));
	 }
	
	 // ---------------- Weight Addition Tests ----------------
	
	 @Test
	 public void testWeightAddition_SameUnit() {
	     Weight result = new Weight(2.0, WeightUnit.KILOGRAM)
	             .add(new Weight(3.0, WeightUnit.KILOGRAM));
	
	     assertEquals(5.0, result.getValue(), EPSILON);
	     assertEquals(WeightUnit.KILOGRAM, result.getUnit());
	 }
	
	 @Test
	 public void testWeightAddition_CrossUnit_KgPlusGram() {
	     Weight result = new Weight(1.0, WeightUnit.KILOGRAM)
	             .add(new Weight(1000.0, WeightUnit.GRAM));
	
	     assertEquals(2.0, result.getValue(), EPSILON);
	     assertEquals(WeightUnit.KILOGRAM, result.getUnit());
	 }
	
	 @Test
	 public void testWeightAddition_CrossUnit_PoundPlusKg() {
	     Weight result = new Weight(2.20462, WeightUnit.POUND)
	             .add(new Weight(1.0, WeightUnit.KILOGRAM));
	
	     assertEquals(4.40924, result.getValue(), 1e-4);
	     assertEquals(WeightUnit.POUND, result.getUnit());
	 }
	
	 @Test
	 public void testWeightAddition_ExplicitTargetUnit() {
	     Weight result = Weight.add(
	             new Weight(1.0, WeightUnit.KILOGRAM),
	             new Weight(1000.0, WeightUnit.GRAM),
	             WeightUnit.GRAM);
	
	     assertEquals(2000.0, result.getValue(), EPSILON);
	     assertEquals(WeightUnit.GRAM, result.getUnit());
	 }
	
	 @Test
	 public void testWeightAddition_Commutativity() {
	     Weight w1 = new Weight(1.0, WeightUnit.KILOGRAM);
	     Weight w2 = new Weight(1000.0, WeightUnit.GRAM);
	
	     assertTrue(w1.add(w2).equals(w2.add(w1)));
	 }
	
	 @Test
	 public void testWeightAddition_WithZero() {
	     Weight result = new Weight(5.0, WeightUnit.KILOGRAM)
	             .add(new Weight(0.0, WeightUnit.GRAM));
	
	     assertEquals(5.0, result.getValue(), EPSILON);
	 }
	
	 @Test
	 public void testWeightAddition_NegativeValue() {
	     Weight result = new Weight(5.0, WeightUnit.KILOGRAM)
	             .add(new Weight(-2000.0, WeightUnit.GRAM));
	
	     assertEquals(3.0, result.getValue(), EPSILON);
	 }
	
	 @Test
	 public void testWeightAddition_LargeValues() {
	     Weight result = new Weight(1e6, WeightUnit.KILOGRAM)
	             .add(new Weight(1e6, WeightUnit.KILOGRAM));
	
	     assertEquals(2e6, result.getValue(), EPSILON);
	 }
    
    
}