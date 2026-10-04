// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package predicates

import (
	"bytes"
	"encoding/json"
	"sync"
	"testing"

	"github.com/policylabs/attestation"
	papi "github.com/policylabs/policy/api/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	testCaseInvalidJSON = "invalid JSON"
	testCaseEmptyData   = "empty data"
	testCaseNullData    = "null data"
)

func TestNew(t *testing.T) {
	parser := New()
	if parser == nil {
		t.Fatal("New() returned nil")
	}
}

func TestParser_Parse(t *testing.T) {
	tests := []struct {
		name         string
		data         []byte
		wantErr      bool
		expectedType attestation.PredicateType
	}{
		{
			name: "parses PolicySet predicate",
			data: []byte(`{
				"id": "test-policyset",
				"meta": {
					"runtime": "starlark/v0",
					"version": 1
				},
				"policies": [
					{
						"id": "test-policy",
						"meta": {"runtime": "starlark/v0"}
					}
				]
			}`),
			wantErr:      false,
			expectedType: PredicateTypePolicySet,
		},
		{
			name: "parses Policy predicate",
			data: []byte(`{
				"id": "standalone-policy",
				"meta": {
					"runtime": "starlark/v0",
					"description": "Standalone policy test",
					"version": 1
				},
				"tenets": [
					{
						"id": "test-tenet",
						"runtime": "starlark/v0",
						"code": "def check(): return True"
					}
				]
			}`),
			wantErr:      false,
			expectedType: PredicateTypePolicy,
		},
		{
			name: "parses PolicyGroup predicate",
			data: []byte(`{
				"id": "security-group",
				"meta": {
					"description": "Security policy group",
					"version": 1,
					"runtime": "starlark/v0"
				},
				"blocks": [
					{
						"id": "block-1",
						"meta": {"description": "Test block"},
						"policies": []
					}
				]
			}`),
			wantErr:      false,
			expectedType: PredicateTypePolicyGroup,
		},
		{
			name: "parses Result predicate",
			data: []byte(`{
				"status": "PASSED",
				"dateStart": "2025-01-15T10:00:00Z",
				"dateEnd": "2025-01-15T10:00:05Z",
				"policy": {
					"id": "test-policy",
					"version": 1
				},
				"evalResults": [
					{
						"id": "tenet-1",
						"status": "PASSED",
						"output": {"verified": true}
					}
				]
			}`),
			wantErr:      false,
			expectedType: PredicateTypeResult,
		},
		{
			name: "parses ResultSet predicate",
			data: []byte(`{
				"status": "PASSED",
				"dateStart": "2025-01-15T11:00:00Z",
				"dateEnd": "2025-01-15T11:00:30Z",
				"policySet": {
					"id": "baseline-set",
					"version": 1
				},
				"results": [
					{
						"status": "PASSED",
						"policy": {"id": "policy-1"}
					}
				]
			}`),
			wantErr:      false,
			expectedType: PredicateTypeResultSet,
		},
		{
			name: "parses ResultGroup predicate",
			data: []byte(`{
				"status": "PASSED",
				"dateStart": "2025-01-15T12:00:00Z",
				"dateEnd": "2025-01-15T12:00:45Z",
				"group": {
					"id": "test-group",
					"version": 1
				},
				"evalResults": [
					{
						"status": "PASSED",
						"id": "block-1",
						"results": []
					}
				]
			}`),
			wantErr:      false,
			expectedType: PredicateTypeResultGroup,
		},
		{
			name:    "fails on invalid JSON",
			data:    []byte(`{invalid json`),
			wantErr: true,
		},
		{
			name:    "fails on empty data",
			data:    []byte(``),
			wantErr: true,
		},
		{
			name:    "fails on null data",
			data:    nil,
			wantErr: true,
		},
		{
			name: "fails on unrecognized structure",
			data: []byte(`{
				"unknown_field": "value",
				"another_field": 123,
				"nested": {
					"data": "that doesn't match any predicate"
				}
			}`),
			wantErr: true,
		},
	}

	parser := New()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pred, err := parser.Parse(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if pred == nil {
					t.Error("Parse() returned nil predicate when expecting success")
					return
				}
				if pred.GetType() != tt.expectedType {
					t.Errorf("Parse() returned type %v, expected %v", pred.GetType(), tt.expectedType)
				}
			}
		})
	}
}

func TestParser_Parse_Concurrency(t *testing.T) {
	// Test that Parse can be called concurrently without issues
	parser := New()

	testData := []struct {
		name string
		data []byte
	}{
		{
			name: "policy",
			data: []byte(`{"id":"p1","meta":{"runtime":"starlark/v0"},"tenets":[{"id":"t1","runtime":"starlark/v0","code":"x"}]}`),
		},
		{
			name: "policyset",
			data: []byte(`{"id":"ps1","meta":{"runtime":"starlark/v0"},"policies":[]}`),
		},
		{
			name: "result",
			data: []byte(`{"status":"PASSED","policy":{"id":"p1"},"evalResults":[]}`),
		},
	}

	var wg sync.WaitGroup
	for range 10 {
		for _, td := range testData {
			wg.Add(1)
			go func(data []byte, name string) {
				defer wg.Done()
				pred, err := parser.Parse(data)
				if err != nil {
					t.Errorf("Concurrent Parse() failed for %s: %v", name, err)
					return
				}
				if pred == nil {
					t.Errorf("Concurrent Parse() returned nil predicate for %s", name)
				}
			}(td.data, td.name)
		}
	}
	wg.Wait()
}

func TestParser_Parse_DataPreservation(t *testing.T) {
	parser := New()

	originalData := []byte(`{
		"id": "verify-policy",
		"meta": {
			"runtime": "starlark/v0",
			"description": "Verification policy",
			"version": 1
		},
		"tenets": [
			{
				"id": "check-signature",
				"runtime": "starlark/v0",
				"code": "def verify(): return True",
				"title": "Verify signature"
			}
		]
	}`)

	pred, err := parser.Parse(originalData)
	if err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}

	if pred == nil {
		t.Fatal("Parse() returned nil predicate")
	}

	// Verify data is preserved
	predData := pred.GetData()
	if predData == nil {
		t.Error("Parse() result has nil data")
		return
	}

	// Data should be preserved
	var parsed, original map[string]interface{}
	if err := json.Unmarshal(predData, &parsed); err != nil {
		t.Errorf("Failed to unmarshal predicate data: %v", err)
	}
	if err := json.Unmarshal(originalData, &original); err != nil {
		t.Errorf("Failed to unmarshal original data: %v", err)
	}

	// Check that key fields are preserved
	if parsed["id"] != original["id"] {
		t.Errorf("ID not preserved: got %v, want %v", parsed["id"], original["id"])
	}
}

func TestParser_ParsePolicySetPredicate(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "valid empty PolicySet",
			data:    []byte(`{}`),
			wantErr: false,
		},
		{
			name: "valid PolicySet with complete structure",
			data: []byte(`{
				"id": "security-baseline-v1",
				"meta": {
					"runtime": "starlark/v0",
					"description": "Security baseline policies for container images",
					"version": 1,
					"enforce": "ON",
					"frameworks": [
						{
							"id": "slsa-v1.0",
							"name": "SLSA Framework",
							"definition": {
								"uri": "https://slsa.dev/spec/v1.0"
							}
						}
					]
				},
				"common": {
					"context": {
						"max_severity": {
							"type": "string",
							"required": true,
							"default": "CRITICAL",
							"description": "Maximum allowed vulnerability severity"
						}
					}
				},
				"policies": [
					{
						"id": "vuln-scan-policy",
						"meta": {
							"runtime": "starlark/v0",
							"description": "Vulnerability scanning policy",
							"enforce": "ON",
							"version": 1
						},
						"tenets": [
							{
								"id": "check-critical-vulns",
								"runtime": "starlark/v0",
								"code": "def evaluate(ctx): return len(ctx.vulns) == 0",
								"title": "No critical vulnerabilities allowed"
							}
						]
					}
				],
				"chain": [
					{
						"predicate": {
							"type": "https://slsa.dev/provenance/v1",
							"selector": "materials[0].digest",
							"runtime": "jq"
						}
					}
				],
				"groups": [
					{
						"id": "supply-chain-group",
						"meta": {
							"description": "Supply chain security policies",
							"version": 1,
							"enforce": "ON"
						}
					}
				]
			}`),
			wantErr: false,
		},
		{
			name:    testCaseInvalidJSON,
			data:    []byte(`{invalid json`),
			wantErr: true,
		},
		{
			name:    testCaseEmptyData,
			data:    []byte(``),
			wantErr: true,
		},
		{
			name:    testCaseNullData,
			data:    nil,
			wantErr: true,
		},
	}

	parser := New()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pred, err := parser.ParsePolicySetPredicate(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParsePolicySetPredicate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if pred == nil {
					t.Error("ParsePolicySetPredicate() returned nil predicate")
					return
				}
				policySet, ok := pred.(*PolicySet)
				if !ok {
					t.Errorf("ParsePolicySetPredicate() returned wrong type: %T", pred)
					return
				}
				if policySet.Parsed == nil {
					t.Error("ParsePolicySetPredicate() returned predicate with nil Parsed field")
				}
				if policySet.Data == nil {
					t.Error("ParsePolicySetPredicate() returned predicate with nil Data field")
				}
			}
		})
	}
}

func TestParser_ParsePolicyPredicate(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "valid empty Policy",
			data:    []byte(`{}`),
			wantErr: false,
		},
		{
			name: "valid Policy with complete structure",
			data: []byte(`{
				"id": "sbom-attestation-policy",
				"source": {
					"id": "sbom-policy-v1",
					"version": 1,
					"location": {
						"uri": "https://policies.example.com/sbom-v1.json"
					}
				},
				"meta": {
					"runtime": "starlark/v0",
					"description": "Validates SBOM attestation presence and content",
					"assert_mode": "AND",
					"version": 2,
					"enforce": "ON",
					"controls": [
						{
							"id": "CTRL-001",
							"class": "supply-chain",
							"framework": "slsa-v1.0",
							"title": "SBOM Generation"
						}
					]
				},
				"context": {
					"allowed_licenses": {
						"type": "array",
						"required": true,
						"value": ["MIT", "Apache-2.0", "BSD-3-Clause"],
						"description": "List of allowed software licenses"
					},
					"min_components": {
						"type": "number",
						"required": false,
						"default": 1,
						"description": "Minimum number of components expected in SBOM"
					}
				},
				"predicates": {
					"types": [
						"https://spdx.dev/Document",
						"https://cyclonedx.org/bom"
					],
					"limit": 1
				},
				"tenets": [
					{
						"id": "check-sbom-present",
						"runtime": "starlark/v0",
						"code": "def evaluate(statements):\n  return len(statements) > 0",
						"title": "SBOM attestation must be present",
						"error": {
							"message": "No SBOM attestation found",
							"guidance": "Ensure your build process generates and attests an SBOM"
						},
						"assessment": {
							"message": "SBOM attestation validated successfully"
						},
						"outputs": {
							"component_count": {
								"code": "len(sbom.components)"
							}
						}
					},
					{
						"id": "verify-licenses",
						"runtime": "starlark/v0",
						"code": "def verify(components, allowed):\n  return all(c.license in allowed for c in components)",
						"title": "All component licenses must be approved"
					}
				]
			}`),
			wantErr: false,
		},
		{
			name:    testCaseInvalidJSON,
			data:    []byte(`{invalid json`),
			wantErr: true,
		},
		{
			name:    testCaseEmptyData,
			data:    []byte(``),
			wantErr: true,
		},
		{
			name:    testCaseNullData,
			data:    nil,
			wantErr: true,
		},
	}

	parser := New()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pred, err := parser.ParsePolicyPredicate(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParsePolicyPredicate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if pred == nil {
					t.Error("ParsePolicyPredicate() returned nil predicate")
					return
				}
				policy, ok := pred.(*Policy)
				if !ok {
					t.Errorf("ParsePolicyPredicate() returned wrong type: %T", pred)
					return
				}
				if policy.Parsed == nil {
					t.Error("ParsePolicyPredicate() returned predicate with nil Parsed field")
				}
				if policy.Data == nil {
					t.Error("ParsePolicyPredicate() returned predicate with nil Data field")
				}
			}
		})
	}
}

func TestParser_ParsePolicyGroupPredicate(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "valid empty PolicyGroup",
			data:    []byte(`{}`),
			wantErr: false,
		},
		{
			name: "valid PolicyGroup with complete structure",
			data: []byte(`{
				"id": "container-security-group",
				"meta": {
					"description": "Container security policy group",
					"version": 3,
					"enforce": "ON",
					"runtime": "starlark/v0",
					"controls": [
						{
							"id": "NIST-800-53-CM-2",
							"class": "configuration-management",
							"framework": "nist-800-53",
							"title": "Baseline Configuration"
						}
					]
				},
				"common": {
					"context": {
						"environment": {
							"type": "string",
							"required": true,
							"description": "Deployment environment (dev, staging, prod)"
						}
					}
				},
				"source": {
					"id": "container-security-v3",
					"version": 3,
					"location": {
						"uri": "https://policies.example.com/container-security.json",
						"digest": {
							"sha256": "a1b2c3d4e5f6"
						}
					}
				},
				"blocks": [
					{
						"id": "image-scanning-block",
						"meta": {
							"description": "Image vulnerability scanning requirements",
							"assert_mode": "AND",
							"enforce": "ON",
							"controls": [
								{
									"id": "IMG-SCAN-001",
									"class": "vulnerability-management",
									"framework": "custom",
									"title": "Container Image Scanning"
								}
							]
						},
						"policies": [
							{
								"id": "no-critical-cves",
								"meta": {
									"runtime": "starlark/v0",
									"description": "No critical CVEs allowed",
									"enforce": "ON",
									"version": 1
								},
								"tenets": [
									{
										"id": "check-severity",
										"runtime": "starlark/v0",
										"code": "def check(vulns): return not any(v.severity == 'CRITICAL' for v in vulns)",
										"title": "Critical vulnerabilities check"
									}
								]
							}
						]
					},
					{
						"id": "provenance-block",
						"meta": {
							"description": "Build provenance verification",
							"assert_mode": "OR",
							"enforce": "ON"
						},
						"policies": [
							{
								"id": "slsa-level-check",
								"meta": {
									"runtime": "starlark/v0",
									"description": "Verify SLSA provenance level",
									"enforce": "ON",
									"version": 1
								}
							}
						]
					}
				]
			}`),
			wantErr: false,
		},
		{
			name:    testCaseInvalidJSON,
			data:    []byte(`{invalid json`),
			wantErr: true,
		},
		{
			name:    testCaseEmptyData,
			data:    []byte(``),
			wantErr: true,
		},
		{
			name:    testCaseNullData,
			data:    nil,
			wantErr: true,
		},
	}

	parser := New()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pred, err := parser.ParsePolicyGroupPredicate(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParsePolicyGroupPredicate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if pred == nil {
					t.Error("ParsePolicyGroupPredicate() returned nil predicate")
					return
				}
				policyGroup, ok := pred.(*PolicyGroup)
				if !ok {
					t.Errorf("ParsePolicyGroupPredicate() returned wrong type: %T", pred)
					return
				}
				if policyGroup.Parsed == nil {
					t.Error("ParsePolicyGroupPredicate() returned predicate with nil Parsed field")
				}
				if policyGroup.Data == nil {
					t.Error("ParsePolicyGroupPredicate() returned predicate with nil Data field")
				}
			}
		})
	}
}

func TestParser_ParseResultPredicate(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "valid empty Result",
			data:    []byte(`{}`),
			wantErr: false,
		},
		{
			name: "valid Result with complete structure",
			data: []byte(`{
				"status": "PASSED",
				"dateStart": "2025-01-15T10:30:00Z",
				"dateEnd": "2025-01-15T10:30:05Z",
				"policy": {
					"id": "sbom-policy-v1",
					"version": 1,
					"location": {
						"uri": "https://policies.example.com/sbom-v1.json"
					}
				},
				"meta": {
					"runtime": "starlark/v0",
					"description": "SBOM validation policy",
					"enforce": "ON",
					"version": 1,
					"controls": [
						{
							"id": "SBOM-001",
							"class": "supply-chain",
							"framework": "slsa-v1.0",
							"title": "Software Bill of Materials"
						}
					]
				},
				"context": {
					"allowed_licenses": ["MIT", "Apache-2.0", "BSD-3-Clause"],
					"min_components": 5
				},
				"subject": {
					"name": "registry.example.com/myapp:v1.0.0",
					"digest": {
						"sha256": "abc123def456"
					}
				},
				"evalResults": [
					{
						"id": "check-sbom-present",
						"status": "PASSED",
						"date": "2025-01-15T10:30:02Z",
						"output": {
							"component_count": 42,
							"has_dependencies": true
						},
						"statements": [
							{
								"type": "https://spdx.dev/Document",
								"attestation": {
									"uri": "https://attestations.example.com/sbom-abc123.json",
									"digest": {
										"sha256": "def789abc012"
									}
								},
								"identities": [
									{
										"id": "build-system@example.com"
									}
								]
							}
						],
						"assessment": {
							"message": "SBOM attestation validated successfully"
						}
					},
					{
						"id": "verify-licenses",
						"status": "PASSED",
						"date": "2025-01-15T10:30:04Z",
						"output": {
							"all_licenses_approved": true,
							"unapproved_count": 0
						},
						"assessment": {
							"message": "All component licenses are approved"
						}
					}
				],
				"chain": [
					{
						"source": {
							"name": "container-image",
							"digest": {
								"sha256": "abc123def456"
							}
						},
						"destination": {
							"name": "source-repo",
							"digest": {
								"sha256": "source789"
							}
						},
						"link": {
							"type": "https://slsa.dev/provenance/v1",
							"attestation": {
								"uri": "https://attestations.example.com/prov-abc123.json"
							}
						}
					}
				]
			}`),
			wantErr: false,
		},
		{
			name: "valid Result with FAILED status",
			data: []byte(`{
				"status": "FAILED",
				"dateStart": "2025-01-15T11:00:00Z",
				"dateEnd": "2025-01-15T11:00:03Z",
				"policy": {
					"id": "vuln-scan-policy",
					"version": 2
				},
				"evalResults": [
					{
						"id": "check-critical-vulns",
						"status": "FAILED",
						"date": "2025-01-15T11:00:02Z",
						"error": {
							"message": "Critical vulnerabilities detected",
							"guidance": "Update vulnerable components or apply security patches"
						},
						"output": {
							"critical_count": 3,
							"high_count": 7
						}
					}
				]
			}`),
			wantErr: false,
		},
		{
			name:    testCaseInvalidJSON,
			data:    []byte(`{invalid json`),
			wantErr: true,
		},
		{
			name:    testCaseEmptyData,
			data:    []byte(``),
			wantErr: true,
		},
		{
			name:    testCaseNullData,
			data:    nil,
			wantErr: true,
		},
	}

	parser := New()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pred, err := parser.ParseResultPredicate(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseResultPredicate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if pred == nil {
					t.Error("ParseResultPredicate() returned nil predicate")
					return
				}
				result, ok := pred.(*Result)
				if !ok {
					t.Errorf("ParseResultPredicate() returned wrong type: %T", pred)
					return
				}
				if result.Parsed == nil {
					t.Error("ParseResultPredicate() returned predicate with nil Parsed field")
				}
				if result.Data == nil {
					t.Error("ParseResultPredicate() returned predicate with nil Data field")
				}
			}
		})
	}
}

func TestParser_ParseResultSetPredicate(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "valid empty ResultSet",
			data:    []byte(`{}`),
			wantErr: false,
		},
		{
			name: "valid ResultSet with complete structure",
			data: []byte(`{
				"policySet": {
					"id": "security-baseline-v1",
					"version": 1,
					"location": {
						"uri": "https://policies.example.com/baseline-v1.json"
					}
				},
				"meta": {
					"runtime": "starlark/v0",
					"description": "Security baseline for production deployments",
					"version": 1,
					"enforce": "ON",
					"frameworks": [
						{
							"id": "slsa-v1.0",
							"name": "SLSA Framework",
							"definition": {
								"uri": "https://slsa.dev/spec/v1.0"
							}
						}
					]
				},
				"status": "PASSED",
				"dateStart": "2025-01-15T14:00:00Z",
				"dateEnd": "2025-01-15T14:00:30Z",
				"subject": {
					"name": "registry.example.com/prod-app:v2.5.0",
					"digest": {
						"sha256": "prod123abc456"
					}
				},
				"common": {
					"context": {
						"environment": "production",
						"criticality": "high"
					}
				},
				"results": [
					{
						"status": "PASSED",
						"policy": {
							"id": "sbom-policy"
						},
						"evalResults": [
							{
								"id": "sbom-present",
								"status": "PASSED",
								"assessment": {
									"message": "SBOM validated"
								}
							}
						]
					},
					{
						"status": "PASSED",
						"policy": {
							"id": "provenance-policy"
						},
						"evalResults": [
							{
								"id": "slsa-level-3",
								"status": "PASSED",
								"assessment": {
									"message": "SLSA Level 3 requirements met"
								}
							}
						]
					},
					{
						"status": "PASSED",
						"policy": {
							"id": "vulnerability-policy"
						},
						"evalResults": [
							{
								"id": "no-critical-vulns",
								"status": "PASSED",
								"output": {
									"total_vulns": 12,
									"critical": 0,
									"high": 2,
									"medium": 5,
									"low": 5
								}
							}
						]
					}
				],
				"groups": [
					{
						"status": "PASSED",
						"group": {
							"id": "supply-chain-group"
						},
						"evalResults": [
							{
								"status": "PASSED",
								"id": "supply-chain-block",
								"results": [
									{
										"status": "PASSED",
										"policy": {
											"id": "dependency-policy"
										}
									}
								]
							}
						]
					}
				]
			}`),
			wantErr: false,
		},
		{
			name: "valid ResultSet with FAILED status",
			data: []byte(`{
				"policySet": {
					"id": "security-baseline-v1",
					"version": 1
				},
				"status": "FAILED",
				"dateStart": "2025-01-15T15:00:00Z",
				"dateEnd": "2025-01-15T15:00:15Z",
				"subject": {
					"name": "registry.example.com/test-app:v1.0.0",
					"digest": {
						"sha256": "test456def789"
					}
				},
				"results": [
					{
						"status": "FAILED",
						"policy": {
							"id": "vuln-policy"
						},
						"evalResults": [
							{
								"id": "critical-check",
								"status": "FAILED",
								"error": {
									"message": "Critical vulnerabilities found",
									"guidance": "Update dependencies"
								}
							}
						]
					}
				],
				"error": {
					"message": "Policy set failed due to critical vulnerabilities"
				}
			}`),
			wantErr: false,
		},
		{
			name:    testCaseInvalidJSON,
			data:    []byte(`{invalid json`),
			wantErr: true,
		},
		{
			name:    testCaseEmptyData,
			data:    []byte(``),
			wantErr: true,
		},
		{
			name:    testCaseNullData,
			data:    nil,
			wantErr: true,
		},
	}

	parser := New()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pred, err := parser.ParseResultSetPredicate(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseResultSetPredicate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if pred == nil {
					t.Error("ParseResultSetPredicate() returned nil predicate")
					return
				}
				resultSet, ok := pred.(*ResultSet)
				if !ok {
					t.Errorf("ParseResultSetPredicate() returned wrong type: %T", pred)
					return
				}
				if resultSet.Parsed == nil {
					t.Error("ParseResultSetPredicate() returned predicate with nil Parsed field")
				}
				if resultSet.Data == nil {
					t.Error("ParseResultSetPredicate() returned predicate with nil Data field")
				}
			}
		})
	}
}

func TestParser_ParseResultGroupPredicate(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "valid empty ResultGroup",
			data:    []byte(`{}`),
			wantErr: false,
		},
		{
			name: "valid ResultGroup with complete structure",
			data: []byte(`{
				"status": "PASSED",
				"dateStart": "2025-01-15T16:00:00Z",
				"dateEnd": "2025-01-15T16:00:45Z",
				"group": {
					"id": "container-security-v3",
					"version": 3,
					"location": {
						"uri": "https://policies.example.com/container-security.json",
						"digest": {
							"sha256": "grp123abc456"
						}
					}
				},
				"meta": {
					"description": "Container security policy group",
					"version": 3,
					"enforce": "ON",
					"runtime": "starlark/v0",
					"controls": [
						{
							"id": "NIST-800-53-CM-2",
							"class": "configuration-management",
							"framework": "nist-800-53",
							"title": "Baseline Configuration"
						}
					]
				},
				"context": {
					"environment": "staging",
					"scan_depth": "full"
				},
				"subject": {
					"name": "registry.example.com/staging-app:v1.2.3",
					"digest": {
						"sha256": "staging789xyz012"
					}
				},
				"common": {
					"context": {
						"max_age_days": 90,
						"require_signatures": true
					}
				},
				"evalResults": [
					{
						"status": "PASSED",
						"id": "image-scanning-block",
						"meta": {
							"description": "Image vulnerability scanning requirements",
							"assert_mode": "AND",
							"enforce": "ON"
						},
						"results": [
							{
								"status": "PASSED",
								"policy": {
									"id": "no-critical-cves"
								},
								"evalResults": [
									{
										"id": "check-severity",
										"status": "PASSED",
										"output": {
											"scanned_packages": 234,
											"critical_vulns": 0,
											"high_vulns": 1
										},
										"assessment": {
											"message": "No critical vulnerabilities detected"
										}
									}
								]
							},
							{
								"status": "PASSED",
								"policy": {
									"id": "scan-recency"
								},
								"evalResults": [
									{
										"id": "check-scan-date",
										"status": "PASSED",
										"output": {
											"scan_age_hours": 2
										}
									}
								]
							}
						]
					},
					{
						"status": "PASSED",
						"id": "provenance-block",
						"meta": {
							"description": "Build provenance verification",
							"assert_mode": "OR",
							"enforce": "ON"
						},
						"results": [
							{
								"status": "PASSED",
								"policy": {
									"id": "slsa-level-check"
								},
								"evalResults": [
									{
										"id": "verify-slsa-3",
										"status": "PASSED",
										"output": {
											"slsa_level": 3,
											"builder_id": "https://github.com/slsa-framework/slsa-github-generator"
										}
									}
								]
							}
						]
					}
				],
				"chain": [
					{
						"source": {
							"name": "container-image",
							"digest": {
								"sha256": "staging789xyz012"
							}
						},
						"destination": {
							"name": "git-commit",
							"digest": {
								"sha1": "commit456abc789"
							}
						},
						"link": {
							"type": "https://slsa.dev/provenance/v1",
							"attestation": {
								"uri": "https://attestations.example.com/prov-staging.json"
							}
						}
					}
				]
			}`),
			wantErr: false,
		},
		{
			name: "valid ResultGroup with FAILED block",
			data: []byte(`{
				"status": "FAILED",
				"dateStart": "2025-01-15T17:00:00Z",
				"dateEnd": "2025-01-15T17:00:20Z",
				"group": {
					"id": "security-group-v1",
					"version": 1
				},
				"subject": {
					"name": "registry.example.com/failed-app:v0.1.0"
				},
				"evalResults": [
					{
						"status": "FAILED",
						"id": "compliance-block",
						"results": [
							{
								"status": "FAILED",
								"policy": {
									"id": "license-compliance"
								},
								"evalResults": [
									{
										"id": "check-licenses",
										"status": "FAILED",
										"error": {
											"message": "Unapproved licenses detected: GPL-3.0",
											"guidance": "Replace components with GPL-3.0 license"
										}
									}
								]
							}
						],
						"error": {
							"message": "Block failed due to license violations"
						}
					}
				],
				"Error": "Policy group evaluation failed"
			}`),
			wantErr: false,
		},
		{
			name:    testCaseInvalidJSON,
			data:    []byte(`{invalid json`),
			wantErr: true,
		},
		{
			name:    testCaseEmptyData,
			data:    []byte(``),
			wantErr: true,
		},
		{
			name:    testCaseNullData,
			data:    nil,
			wantErr: true,
		},
	}

	parser := New()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pred, err := parser.ParseResultGroupPredicate(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseResultGroupPredicate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if pred == nil {
					t.Error("ParseResultGroupPredicate() returned nil predicate")
					return
				}
				resultGroup, ok := pred.(*ResultGroup)
				if !ok {
					t.Errorf("ParseResultGroupPredicate() returned wrong type: %T", pred)
					return
				}
				if resultGroup.Parsed == nil {
					t.Error("ParseResultGroupPredicate() returned predicate with nil Parsed field")
				}
				if resultGroup.Data == nil {
					t.Error("ParseResultGroupPredicate() returned predicate with nil Data field")
				}
			}
		})
	}
}

func TestParser_SupportsType(t *testing.T) {
	tests := []struct {
		name      string
		predTypes []attestation.PredicateType
		want      bool
	}{
		{
			name:      "supports Policy type",
			predTypes: []attestation.PredicateType{PredicateTypePolicy},
			want:      true,
		},
		{
			name:      "supports PolicySet type",
			predTypes: []attestation.PredicateType{PredicateTypePolicySet},
			want:      true,
		},
		{
			name:      "supports PolicyGroup type",
			predTypes: []attestation.PredicateType{PredicateTypePolicyGroup},
			want:      true,
		},
		{
			name:      "supports Result type",
			predTypes: []attestation.PredicateType{PredicateTypeResult},
			want:      true,
		},
		{
			name:      "supports ResultSet type",
			predTypes: []attestation.PredicateType{PredicateTypeResultSet},
			want:      true,
		},
		{
			name:      "supports ResultGroup type",
			predTypes: []attestation.PredicateType{PredicateTypeResultGroup},
			want:      true,
		},
		{
			name:      "supports multiple types",
			predTypes: []attestation.PredicateType{PredicateTypePolicy, PredicateTypeResult},
			want:      true,
		},
		{
			name:      "unsupported type",
			predTypes: []attestation.PredicateType{"https://example.com/unknown"},
			want:      false,
		},
		{
			name:      "mixed supported and unsupported types",
			predTypes: []attestation.PredicateType{PredicateTypePolicy, "https://example.com/unknown"},
			want:      true,
		},
		{
			name:      "empty types",
			predTypes: []attestation.PredicateType{},
			want:      false,
		},
		{
			name:      "nil types",
			predTypes: nil,
			want:      false,
		},
	}

	parser := New()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parser.SupportsType(tt.predTypes...)
			if got != tt.want {
				t.Errorf("SupportsType() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestParser_ParsePolicySetPredicate_DataPreservation tests that the original data is preserved
func TestParser_ParsePolicySetPredicate_DataPreservation(t *testing.T) {
	parser := New()
	originalData := []byte(`{
		"id":"compliance-policyset-v2",
		"meta":{
			"runtime":"starlark/v0",
			"description":"Compliance policies for production",
			"version":2,
			"enforce":"ON"
		},
		"policies":[
			{
				"id":"audit-policy",
				"meta":{"runtime":"starlark/v0","version":1}
			}
		]
	}`)

	pred, err := parser.ParsePolicySetPredicate(originalData)
	if err != nil {
		t.Fatalf("ParsePolicySetPredicate() failed: %v", err)
	}

	policySet := pred.(*PolicySet) //nolint:errcheck,forcetypeassert
	if !bytes.Equal(policySet.Data, originalData) {
		t.Errorf("Data not preserved. Got %s, want %s", policySet.Data, originalData)
	}

	// Verify it can be unmarshaled back
	var roundTrip papi.PolicySet
	if err := protojson.Unmarshal(policySet.Data, &roundTrip); err != nil {
		t.Errorf("Failed to unmarshal preserved data: %v", err)
	}

	// Verify parsed data matches
	if policySet.Parsed.Id != "compliance-policyset-v2" {
		t.Errorf("Expected id='compliance-policyset-v2', got '%s'", policySet.Parsed.Id)
	}
	if len(policySet.Parsed.Policies) != 1 {
		t.Errorf("Expected 1 policy, got %d", len(policySet.Parsed.Policies))
	}
}

// TestParser_ParsePolicyPredicate_DataPreservation tests that the original data is preserved
func TestParser_ParsePolicyPredicate_DataPreservation(t *testing.T) {
	parser := New()
	originalData := []byte(`{
		"id":"image-signature-policy",
		"meta":{
			"runtime":"starlark/v0",
			"description":"Verify image signatures",
			"enforce":"ON",
			"version":3
		},
		"tenets":[
			{
				"id":"verify-cosign",
				"runtime":"starlark/v0",
				"code":"def check(sigs): return len(sigs) > 0",
				"title":"Image must have valid signatures"
			}
		]
	}`)

	pred, err := parser.ParsePolicyPredicate(originalData)
	if err != nil {
		t.Fatalf("ParsePolicyPredicate() failed: %v", err)
	}

	policy := pred.(*Policy) //nolint:errcheck,forcetypeassert
	if !bytes.Equal(policy.Data, originalData) {
		t.Errorf("Data not preserved. Got %s, want %s", policy.Data, originalData)
	}

	// Verify it can be unmarshaled back
	var roundTrip papi.Policy
	if err := protojson.Unmarshal(policy.Data, &roundTrip); err != nil {
		t.Errorf("Failed to unmarshal preserved data: %v", err)
	}

	// Verify parsed data matches
	if policy.Parsed.Id != "image-signature-policy" {
		t.Errorf("Expected id='image-signature-policy', got '%s'", policy.Parsed.Id)
	}
	if len(policy.Parsed.Tenets) != 1 {
		t.Errorf("Expected 1 tenet, got %d", len(policy.Parsed.Tenets))
	}
}

// TestParser_ParseResultPredicate_DataPreservation tests that the original data is preserved
func TestParser_ParseResultPredicate_DataPreservation(t *testing.T) {
	parser := New()
	originalData := []byte(`{
		"status":"PASSED",
		"dateStart":"2025-01-15T12:00:00Z",
		"dateEnd":"2025-01-15T12:00:10Z",
		"policy":{"id":"test-policy","version":1},
		"evalResults":[
			{
				"id":"check-1",
				"status":"PASSED",
				"output":{"verified":true}
			}
		],
		"subject":{
			"name":"test-artifact",
			"digest":{"sha256":"abc123"}
		}
	}`)

	pred, err := parser.ParseResultPredicate(originalData)
	if err != nil {
		t.Fatalf("ParseResultPredicate() failed: %v", err)
	}

	result := pred.(*Result) //nolint:errcheck,forcetypeassert
	if !bytes.Equal(result.Data, originalData) {
		t.Errorf("Data not preserved. Got %s, want %s", result.Data, originalData)
	}

	// Verify it can be unmarshaled back
	var roundTrip papi.Result
	if err := protojson.Unmarshal(result.Data, &roundTrip); err != nil {
		t.Errorf("Failed to unmarshal preserved data: %v", err)
	}

	// Verify parsed data matches
	if result.Parsed.Status != "PASSED" {
		t.Errorf("Expected status='PASSED', got '%s'", result.Parsed.Status)
	}
	if len(result.Parsed.EvalResults) != 1 {
		t.Errorf("Expected 1 eval result, got %d", len(result.Parsed.EvalResults))
	}
	if result.Parsed.EvalResults[0].Id != "check-1" {
		t.Errorf("Expected eval result id='check-1', got '%s'", result.Parsed.EvalResults[0].Id)
	}
}
