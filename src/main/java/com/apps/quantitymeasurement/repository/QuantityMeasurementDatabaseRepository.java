package com.apps.quantitymeasurement.repository;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;

import com.apps.quantitymeasurement.model.QuantityMeasurementEntity;
import com.apps.quantitymeasurement.util.ConnectionPool;

public class QuantityMeasurementDatabaseRepository implements IQuantityMeasurementRepository {

    public QuantityMeasurementDatabaseRepository() {
        createTableIfNotExists();
    }

    private void createTableIfNotExists() {

        String sql = """
            CREATE TABLE IF NOT EXISTS QUANTITY_MEASUREMENT_ENTITY (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                operation VARCHAR(50),
                operand1 VARCHAR(100),
                operand2 VARCHAR(100),
                result VARCHAR(100),
                error_message VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """;

        try (Connection connection = ConnectionPool.getConnection();
             Statement stmt = connection.createStatement()) {

            stmt.execute(sql);

        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void saveMeasurement(QuantityMeasurementEntity entity) {

        String sql = """
            INSERT INTO QUANTITY_MEASUREMENT_ENTITY
            (operation, operand1, operand2, result, error_message)
            VALUES (?, ?, ?, ?, ?)
            """;

        try (Connection connection = ConnectionPool.getConnection();
             java.sql.PreparedStatement ps = connection.prepareStatement(sql)) {

        	ps.setString(1, entity.operation);
        	ps.setString(2, entity.thisValue + " " + entity.thisUnit);
        	ps.setString(3, entity.thatValue + " " + entity.thatUnit);
        	ps.setString(4, entity.resultValue + " " + entity.resultUnit);
        	ps.setString(5, entity.errorMessage);

            ps.executeUpdate();

        } catch (SQLException e) {
            throw new RuntimeException("Failed to save measurement", e);
        }
    }

    @Override
    public List<QuantityMeasurementEntity> findAll() {

        List<QuantityMeasurementEntity> list = new java.util.ArrayList<>();

        String sql = "SELECT * FROM QUANTITY_MEASUREMENT_ENTITY";

        try (Connection connection = ConnectionPool.getConnection();
             java.sql.PreparedStatement ps = connection.prepareStatement(sql);
             java.sql.ResultSet rs = ps.executeQuery()) {

        	while (rs.next()) {

        	    System.out.println(
        	        rs.getString("operation") + " | " +
        	        rs.getString("operand1") + " | " +
        	        rs.getString("operand2") + " | " +
        	        rs.getString("result")
        	    );

        	}

        } catch (SQLException e) {
            throw new RuntimeException(e);
        }

        return list;
    }

	@Override
	public void save(QuantityMeasurementEntity entity) {
		// TODO Auto-generated method stub
		
	}
}