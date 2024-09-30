// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// V1SubmitTreeSignaturesRequest v1 submit tree signatures request
//
// swagger:model v1SubmitTreeSignaturesRequest
type V1SubmitTreeSignaturesRequest struct {

	// pubkey
	Pubkey string `json:"pubkey,omitempty"`

	// round Id
	RoundID string `json:"roundId,omitempty"`

	// tree signatures
	TreeSignatures string `json:"treeSignatures,omitempty"`
}

// Validate validates this v1 submit tree signatures request
func (m *V1SubmitTreeSignaturesRequest) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this v1 submit tree signatures request based on context it is used
func (m *V1SubmitTreeSignaturesRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *V1SubmitTreeSignaturesRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *V1SubmitTreeSignaturesRequest) UnmarshalBinary(b []byte) error {
	var res V1SubmitTreeSignaturesRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}