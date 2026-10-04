// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package predicates

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/policylabs/attestation"
	papi "github.com/policylabs/policy/api/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// hjsonPolicySet is a policy set as humans write it: comments, unquoted
// keys, a multiline description and trailing commas.
const hjsonPolicySet = `{
    // A policy set written in HJSON
    id: hjson-set
    meta: {
        description:
            '''
            # Release verification
            Multi-line markdown.
            '''
        version: 1,
    }
    common: {
        identities: [
            {
                sigstore: {
                    issuerMatch: { exact: "https://token.actions.githubusercontent.com" }
                    identityMatch: { regex: "^https://github\\.com/org/repo/\\.github/workflows/release\\.yaml@refs/tags/v.*$" }
                }
            }
        ]
    }
    policies: [
        {
            id: slsa-builder-id
            source: { location: { uri: "git+https://github.com/carabiner-dev/policies#slsa/slsa-builder-id.json" } }
        },
    ]
}`

const hjsonPolicy = `{
    id: has-provenance
    meta: { description: "Requires a provenance attestation" }
    tenets: [
        {
            id: exists
            predicates: { types: ["https://slsa.dev/provenance/v1"] }
            code: "size(predicates) > 0"
        }
    ]
}`

const hjsonPolicyGroup = `{
    id: release-group
    meta: { description: "A group" }
    blocks: [
        {
            id: block-a
            policies: [ { id: "has-provenance" } ]
        }
    ]
}`

func TestNormalizeToJSON(t *testing.T) {
	for _, tc := range []struct {
		name          string
		data          string
		wantNotFormat bool
		wantID        any
	}{
		{"json-untouched", `{"id": "x", "meta": {"version": 1}}`, false, "x"},
		{"hjson-converted", "{\n  // comment\n  id: y\n  meta: { version: 1 }\n}", false, "y"},
		{"hjson-braceless-root", "id: z\nmeta: { version: 1 }", false, "z"},
		{"empty", "", true, ""},
		{"whitespace", " \n\t", true, ""},
		{"json-array", `[1, 2]`, true, ""},
		{"json-string", `"just a string"`, true, ""},
		{"binary-garbage", "\x00\x01{{{", true, ""},
		{"hjson-empty-document", "// nothing here\n", true, ""},
		{"json-empty-object-kept", `{}`, false, nil},
		{"unbalanced", "{ id: x", true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := normalizeToJSON([]byte(tc.data))
			if tc.wantNotFormat {
				if !errors.Is(err, attestation.ErrNotCorrectFormat) {
					t.Fatalf("expected ErrNotCorrectFormat, got err=%v out=%q", err, out)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !json.Valid(out) {
				t.Fatalf("normalized output is not JSON: %q", out)
			}
			var doc map[string]any
			if err := json.Unmarshal(out, &doc); err != nil {
				t.Fatal(err)
			}
			if doc["id"] != tc.wantID {
				t.Fatalf("id = %v, want %v", doc["id"], tc.wantID)
			}
		})
	}
}

func TestParser_HJSONPolicyMaterials(t *testing.T) {
	parser := New()

	t.Run("policyset", func(t *testing.T) {
		pred, err := parser.ParsePolicySetPredicate([]byte(hjsonPolicySet))
		if err != nil {
			t.Fatalf("ParsePolicySetPredicate() error = %v", err)
		}
		set, ok := pred.(*PolicySet)
		if !ok {
			t.Fatalf("wrong type %T", pred)
		}
		if set.Parsed.GetId() != "hjson-set" {
			t.Errorf("id = %q", set.Parsed.GetId())
		}
		if set.Parsed.GetMeta().GetVersion() != 1 {
			t.Errorf("version = %d", set.Parsed.GetMeta().GetVersion())
		}
		if got := set.Parsed.GetCommon().GetIdentities()[0].GetSigstore().GetIdentityMatch().GetRegex(); got == "" {
			t.Error("identity regex was lost in normalization")
		}
		if got := set.Parsed.GetPolicies()[0].GetSource().GetLocation().GetUri(); got == "" {
			t.Error("remote reference was lost in normalization")
		}
		// The data exposed downstream is JSON, so consumers that only speak
		// JSON (protojson, the policy parser) can read it back.
		if !json.Valid(set.GetData()) {
			t.Fatalf("GetData() is not JSON: %q", set.GetData())
		}
		reparsed := &papi.PolicySet{}
		if err := protojson.Unmarshal(set.GetData(), reparsed); err != nil {
			t.Fatalf("GetData() does not round-trip through protojson: %v", err)
		}
		if set.GetType() != PredicateTypePolicySet {
			t.Errorf("type = %s", set.GetType())
		}
	})

	t.Run("policy", func(t *testing.T) {
		pred, err := parser.ParsePolicyPredicate([]byte(hjsonPolicy))
		if err != nil {
			t.Fatalf("ParsePolicyPredicate() error = %v", err)
		}
		policy, ok := pred.(*Policy)
		if !ok {
			t.Fatalf("wrong type %T", pred)
		}
		if policy.Parsed.GetId() != "has-provenance" || len(policy.Parsed.GetTenets()) != 1 {
			t.Errorf("unexpected policy: %v", policy.Parsed)
		}
		if !json.Valid(policy.GetData()) {
			t.Error("GetData() is not JSON")
		}
	})

	t.Run("policygroup", func(t *testing.T) {
		pred, err := parser.ParsePolicyGroupPredicate([]byte(hjsonPolicyGroup))
		if err != nil {
			t.Fatalf("ParsePolicyGroupPredicate() error = %v", err)
		}
		group, ok := pred.(*PolicyGroup)
		if !ok {
			t.Fatalf("wrong type %T", pred)
		}
		if group.Parsed.GetId() != "release-group" || len(group.Parsed.GetBlocks()) != 1 {
			t.Errorf("unexpected group: %v", group.Parsed)
		}
	})

	t.Run("dispatcher-detects-hjson-policyset", func(t *testing.T) {
		pred, err := parser.Parse([]byte(hjsonPolicySet))
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		if pred.GetType() != PredicateTypePolicySet {
			t.Errorf("type = %s, want %s", pred.GetType(), PredicateTypePolicySet)
		}
	})

	t.Run("not-a-document-is-not-this-format", func(t *testing.T) {
		for _, data := range []string{"", "   ", "[1,2]", "\"text\""} {
			_, err := parser.ParsePolicySetPredicate([]byte(data))
			if !errors.Is(err, attestation.ErrNotCorrectFormat) {
				t.Errorf("data %q: expected ErrNotCorrectFormat, got %v", data, err)
			}
		}
	})
}
