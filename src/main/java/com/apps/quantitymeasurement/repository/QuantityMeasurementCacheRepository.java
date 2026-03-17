package com.apps.quantitymeasurement.repository;

import java.util.ArrayList;
import java.util.List;

import com.apps.quantitymeasurement.model.QuantityMeasurementEntity;

/**
 * Cache repository for storing quantity measurement operations
 */
public class QuantityMeasurementCacheRepository implements IQuantityMeasurementRepository {

	private static QuantityMeasurementCacheRepository instance;
	
    private final List<QuantityMeasurementEntity> cache = new ArrayList<>();

    // Private constructor for Singleton
    private QuantityMeasurementCacheRepository() {}

    public static QuantityMeasurementCacheRepository getInstance() {
        if (instance == null) {
            instance = new QuantityMeasurementCacheRepository();
        }
        return instance;
    }
    
    @Override
    public void save(QuantityMeasurementEntity entity) {
        cache.add(entity);
    }

    @Override
    public List<QuantityMeasurementEntity> findAll() {
        return cache;
    }

	@Override
	public void saveMeasurement(QuantityMeasurementEntity entity) {
		// TODO Auto-generated method stub
		
	}
}