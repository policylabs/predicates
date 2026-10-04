// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package predicates

import (
	"encoding/json"

	"github.com/policylabs/attestation"
	v1 "github.com/policylabs/policy/api/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// Ensure we are implementing the attestation framework predicate interface
var _ attestation.Predicate = (*ResultSet)(nil)

const PredicateTypeResultSet attestation.PredicateType = "https://carabiner.dev/ampel/resultset/v0"

// Result (or rather predicates.ResultSet) is a wrapper around the policyset
// evaluation results proto message that ampel generates with --attest
type ResultSet struct {
	Parsed       *v1.ResultSet
	Data         []byte
	verification attestation.Verification
	origin       attestation.Subject
}

// GetOrigin calls the underlying method of the same name
func (r *ResultSet) GetOrigin() attestation.Subject {
	return r.origin
}

// SetOrigin calls the underlying method of the same name
func (r *ResultSet) SetOrigin(origin attestation.Subject) {
	r.origin = origin
}

func (r *ResultSet) SetType(attestation.PredicateType) error {
	return nil
}

func (r *ResultSet) GetType() attestation.PredicateType {
	return PredicateTypeResultSet
}

// SetVerification gets the signature verification data from the envelope
// parser before discarding the envelope. This is supposed the be stored
// for later retrieval.
func (r *ResultSet) SetVerification(verification attestation.Verification) {
	r.verification = verification
}

// GetVerification returns the signature verification generated from the
// envelope parser. The verification may contain details about the integrity,
// identity and signature guarding the PolicySet.
func (r *ResultSet) GetVerification() attestation.Verification {
	return r.verification
}

// GetParsed returns the Go policy object.
func (r *ResultSet) GetParsed() any {
	return r.Parsed
}

// GetData returns the policy data serialized as JSON.
func (r *ResultSet) GetData() []byte {
	if r.Data != nil {
		return r.Data
	}

	data, err := protojson.Marshal(r.Parsed)
	if err != nil {
		return nil
	}
	r.Data = data
	return data
}

// MarshalJSON implements the JSON marshaler interface. It reuses any pre
// parsed data already stored in the predicate.
func (r *ResultSet) MarshalJSON() ([]byte, error) {
	// If the predicate was already marshalled, reuse the output
	if r.Data != nil {
		return r.Data, nil
	}

	// Otherwise, marshal the value
	return json.Marshal(r.Parsed)
}
