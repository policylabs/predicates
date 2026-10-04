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
var _ attestation.Predicate = (*Result)(nil)

const (
	PredicateTypeResult  attestation.PredicateType = "https://carabiner.dev/ampel/result/v0"
	PredicateTypeResult0 attestation.PredicateType = "https://carabiner.dev/ampel/results/v0.0.1"
)

// Result (or rather predicates.Result) is a wrapper around the policy evaluation
// results proto message that ampel generates with --attest
type Result struct {
	Parsed       *v1.Result
	Data         []byte
	verification attestation.Verification
	origin       attestation.Subject
}

// GetOrigin calls the underlying method of the same name
func (r *Result) GetOrigin() attestation.Subject {
	return r.origin
}

// SetOrigin calls the underlying method of the same name
func (r *Result) SetOrigin(origin attestation.Subject) {
	r.origin = origin
}

func (r *Result) SetType(attestation.PredicateType) error {
	return nil
}

func (r *Result) GetType() attestation.PredicateType {
	return PredicateTypeResult
}

// SetVerification gets the signature verification data from the envelope
// parser before discarding the envelope. This is supposed the be stored
// for later retrieval.
func (r *Result) SetVerification(verification attestation.Verification) {
	r.verification = verification
}

// GetVerification returns the signature verification generated from the
// envelope parser. The verification may contain details about the integrity,
// identity and signature guarding the PolicySet.
func (r *Result) GetVerification() attestation.Verification {
	return r.verification
}

// GetParsed returns the Go policy object.
func (r *Result) GetParsed() any {
	return r.Parsed
}

// GetData returns the policy data serialized as JSON.
func (r *Result) GetData() []byte {
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
func (r *Result) MarshalJSON() ([]byte, error) {
	// If the predicate was already marshalled, reuse the output
	if r.Data != nil {
		return r.Data, nil
	}

	// Otherwise, marshal the value
	return json.Marshal(r.Parsed)
}
