// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package predicates

import (
	"bytes"
	"encoding/json"

	"github.com/hjson/hjson-go/v4"
	"github.com/policylabs/attestation"
)

// normalizeToJSON returns the JSON form of a policy material document.
// Policies, policy sets and groups are authored in JSON or HJSON (comments,
// unquoted keys, multiline strings); attestations only ever carry JSON. Valid
// JSON is returned untouched, HJSON is converted, and data that is neither
// (or that does not describe an object) is reported as not being a policy
// document at all through attestation.ErrNotCorrectFormat, so the caller
// can move on to other predicate parsers.
func normalizeToJSON(data []byte) ([]byte, error) {
	// HJSON accepts a braceless root object, so empty input would parse
	// as an empty document. Reject it explicitly.
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, attestation.ErrNotCorrectFormat
	}
	if json.Valid(data) {
		if !isJSONObject(data) {
			return nil, attestation.ErrNotCorrectFormat
		}
		return data, nil
	}

	// HJSON is lenient (braceless roots, bare words as strings), so noise
	// can parse as an empty object. Only a non-empty object counts as a
	// human-authored policy document.
	var parsed any
	if err := hjson.Unmarshal(data, &parsed); err != nil {
		return nil, attestation.ErrNotCorrectFormat
	}
	doc, ok := parsed.(map[string]any)
	if !ok || len(doc) == 0 {
		return nil, attestation.ErrNotCorrectFormat
	}
	normalized, err := json.Marshal(parsed)
	if err != nil {
		return nil, attestation.ErrNotCorrectFormat
	}
	return normalized, nil
}

// isJSONObject reports if a valid JSON document is an object.
func isJSONObject(data []byte) bool {
	trimmed := bytes.TrimLeft(data, " \t\r\n")
	return len(trimmed) > 0 && trimmed[0] == '{'
}
