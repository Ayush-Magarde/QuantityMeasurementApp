# QuantityMeasurementApp

---

## 🧩 UC1 – Feet Equality

- Implements value-based equality for feet measurements using an overridden `equals()` method.
- Establishes object equality semantics as the foundation for future unit comparisons.

---

## 🧩 UC2 – Inches Equality

- Extends value-based equality comparison to inches measurements using a dedicated `Inches` class.
- Maintains independent unit validation while reinforcing equality behaviour across measurement types.

---

## 🧩 UC3 – Generic Length

- Refactors unit-specific classes into a unified `Length` abstraction using a `LengthUnit` enum.
- Eliminates duplicated logic using the **DRY principle** while enabling cross-unit equality comparison.

---

## 🧩 UC4 – Extended Unit Support

- Adds Yards and Centimeters to the `LengthUnit` enum with conversion factors.
- Demonstrates scalability by enabling seamless cross-unit equality without introducing new classes.

---

## 🧩 UC5 – Unit-to-Unit Conversion

- Introduces explicit conversion operations between supported length units.
- Extends the Length API while preserving mathematical equivalence and precision.

---

## 🧩 UC6 – Length Addition Operation

- Introduces addition between length measurements with automatic unit normalization.
- Returns a new immutable `Length` result while preserving mathematical accuracy.

---

## 🧩 UC7 – Addition with Target Unit Specification

- Allows explicit specification of result units independent of operand units.
- Enhances API flexibility while preserving immutability and precision.

---

## 🧩 UC8 – Standalone Unit Refactor

- Extracts `LengthUnit` into a standalone enum responsible for all unit conversion logic.
- Improves architectural separation by delegating conversions to units, reducing coupling and enabling scalable support for future measurement categories.

---

## 🧩 UC9 – Weight Measurement Support

- Introduces a weight measurement category with `Weight` and `WeightUnit` supporting kilograms, grams, and pounds.
- Enables equality, conversion, and addition operations for weight while preserving strict separation from length measurements and stabilizing the shared measurement architecture.

---

## 🧩 UC10 – Generic Quantity Architecture

- Introduces a generic `Quantity<U extends IMeasurable>` model enabling multiple measurement categories through a shared abstraction.
- Eliminates category-specific duplication by unifying equality, conversion, and addition logic into a single scalable architecture.

---

## 🧩 UC11 – Volume Measurement Support

- Adds a new measurement category using `VolumeUnit` (Litre, Millilitre, Gallon) implemented through the generic `Quantity<U>` architecture.
- Validates that new measurement types integrate without modifying existing quantity logic, proving true multi-category scalability.

---

## 🧩 UC12 – Subtraction and Division Operations

- Introduces subtraction between quantities with automatic cross-unit normalization while preserving immutability.
- Adds division support producing a dimensionless ratio, enabling comparative analysis across measurements of the same category.

---

## 🧩 UC13 – Centralized Arithmetic Logic (DRY Refactor)

- Refactors addition, subtraction, and division to use a centralized arithmetic helper, eliminating duplicated validation and conversion logic.
- Improves maintainability and scalability while preserving all existing behaviour and public APIs.

---

## 🧩 UC14 – Temperature Measurement (Selective Arithmetic Support)

- Introduces temperature measurements using `TemperatureUnit` integrated into the generic `Quantity<U>` architecture with support for Celsius, Fahrenheit, and Kelvin conversions.
- Applies capability-based validation to allow only supported operations, preventing invalid arithmetic while maintaining backward compatibility for existing measurement categories.

---
