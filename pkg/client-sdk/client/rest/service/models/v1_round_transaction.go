// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// V1RoundTransaction v1 round transaction
//
// swagger:model v1RoundTransaction
type V1RoundTransaction struct {

	// claimed boarding utxos
	ClaimedBoardingUtxos []*V1Outpoint `json:"claimedBoardingUtxos"`

	// spendable vtxos
	SpendableVtxos []*V1Vtxo `json:"spendableVtxos"`

	// spent vtxos
	SpentVtxos []*V1Outpoint `json:"spentVtxos"`

	// txid
	Txid string `json:"txid,omitempty"`
}

// Validate validates this v1 round transaction
func (m *V1RoundTransaction) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateClaimedBoardingUtxos(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSpendableVtxos(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSpentVtxos(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *V1RoundTransaction) validateClaimedBoardingUtxos(formats strfmt.Registry) error {
	if swag.IsZero(m.ClaimedBoardingUtxos) { // not required
		return nil
	}

	for i := 0; i < len(m.ClaimedBoardingUtxos); i++ {
		if swag.IsZero(m.ClaimedBoardingUtxos[i]) { // not required
			continue
		}

		if m.ClaimedBoardingUtxos[i] != nil {
			if err := m.ClaimedBoardingUtxos[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("claimedBoardingUtxos" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("claimedBoardingUtxos" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *V1RoundTransaction) validateSpendableVtxos(formats strfmt.Registry) error {
	if swag.IsZero(m.SpendableVtxos) { // not required
		return nil
	}

	for i := 0; i < len(m.SpendableVtxos); i++ {
		if swag.IsZero(m.SpendableVtxos[i]) { // not required
			continue
		}

		if m.SpendableVtxos[i] != nil {
			if err := m.SpendableVtxos[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("spendableVtxos" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("spendableVtxos" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *V1RoundTransaction) validateSpentVtxos(formats strfmt.Registry) error {
	if swag.IsZero(m.SpentVtxos) { // not required
		return nil
	}

	for i := 0; i < len(m.SpentVtxos); i++ {
		if swag.IsZero(m.SpentVtxos[i]) { // not required
			continue
		}

		if m.SpentVtxos[i] != nil {
			if err := m.SpentVtxos[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("spentVtxos" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("spentVtxos" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this v1 round transaction based on the context it is used
func (m *V1RoundTransaction) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateClaimedBoardingUtxos(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateSpendableVtxos(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateSpentVtxos(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *V1RoundTransaction) contextValidateClaimedBoardingUtxos(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.ClaimedBoardingUtxos); i++ {

		if m.ClaimedBoardingUtxos[i] != nil {

			if swag.IsZero(m.ClaimedBoardingUtxos[i]) { // not required
				return nil
			}

			if err := m.ClaimedBoardingUtxos[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("claimedBoardingUtxos" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("claimedBoardingUtxos" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *V1RoundTransaction) contextValidateSpendableVtxos(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.SpendableVtxos); i++ {

		if m.SpendableVtxos[i] != nil {

			if swag.IsZero(m.SpendableVtxos[i]) { // not required
				return nil
			}

			if err := m.SpendableVtxos[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("spendableVtxos" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("spendableVtxos" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *V1RoundTransaction) contextValidateSpentVtxos(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.SpentVtxos); i++ {

		if m.SpentVtxos[i] != nil {

			if swag.IsZero(m.SpentVtxos[i]) { // not required
				return nil
			}

			if err := m.SpentVtxos[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("spentVtxos" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("spentVtxos" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *V1RoundTransaction) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *V1RoundTransaction) UnmarshalBinary(b []byte) error {
	var res V1RoundTransaction
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
