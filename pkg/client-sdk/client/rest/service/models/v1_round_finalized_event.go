// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// V1RoundFinalizedEvent v1 round finalized event
//
// swagger:model v1RoundFinalizedEvent
type V1RoundFinalizedEvent struct {

	// id
	ID string `json:"id,omitempty"`

	// round txid
	RoundTxid string `json:"roundTxid,omitempty"`
}

// Validate validates this v1 round finalized event
func (m *V1RoundFinalizedEvent) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this v1 round finalized event based on context it is used
func (m *V1RoundFinalizedEvent) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *V1RoundFinalizedEvent) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *V1RoundFinalizedEvent) UnmarshalBinary(b []byte) error {
	var res V1RoundFinalizedEvent
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
