package com.apps.quantitymeasurement.dto;

public class QuantityInputDTO {

    private QuantityDTO thisQuantityDTO;
    private QuantityDTO thatQuantityDTO;
    private QuantityDTO targetQuantityDTO; // ✅ added

    public QuantityInputDTO() {
    }

    public QuantityInputDTO(QuantityDTO thisQuantityDTO, QuantityDTO thatQuantityDTO) {
        this.thisQuantityDTO = thisQuantityDTO;
        this.thatQuantityDTO = thatQuantityDTO;
    }

    public QuantityInputDTO(QuantityDTO thisQuantityDTO,
                            QuantityDTO thatQuantityDTO,
                            QuantityDTO targetQuantityDTO) {
        this.thisQuantityDTO = thisQuantityDTO;
        this.thatQuantityDTO = thatQuantityDTO;
        this.targetQuantityDTO = targetQuantityDTO;
    }

    public QuantityDTO getThisQuantityDTO() {
        return thisQuantityDTO;
    }

    public void setThisQuantityDTO(QuantityDTO thisQuantityDTO) {
        this.thisQuantityDTO = thisQuantityDTO;
    }

    public QuantityDTO getThatQuantityDTO() {
        return thatQuantityDTO;
    }

    public void setThatQuantityDTO(QuantityDTO thatQuantityDTO) {
        this.thatQuantityDTO = thatQuantityDTO;
    }

    public QuantityDTO getTargetQuantityDTO() {   // ✅ now exists
        return targetQuantityDTO;
    }

    public void setTargetQuantityDTO(QuantityDTO targetQuantityDTO) {
        this.targetQuantityDTO = targetQuantityDTO;
    }
}