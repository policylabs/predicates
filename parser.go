// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package predicates

import (
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/carabiner-dev/attestation"
	papi "github.com/policylabs/policy/api/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// PredicateTypes is a slice of all the predicate types
var PredicateTypes = []attestation.PredicateType{
	PredicateTypePolicy,
	PredicateTypePolicySet,
	PredicateTypePolicyGroup,

	PredicateTypeResult,
	PredicateTypeResultSet,
	PredicateTypeResultGroup,

	// Old constants
	PredicateTypePolicy0,
	PredicateTypePolicySet0,
	PredicateTypeResult0,
}

func New() *Parser {
	return &Parser{}
}

type Parser struct{}

// Parse takes JSON data and returns any of the supported predicates if it parses
func (p *Parser) Parse(data []byte) (attestation.Predicate, error) {
	var o sync.Once
	var pred attestation.Predicate

	// This function catches the first predicate to be successfully parsed
	setPredicateIfNotNil := func(a attestation.Predicate, err error) {
		if err != nil {
			return
		}
		if pred != nil {
			return
		}
		o.Do(func() { pred = a })
	}

	var wg sync.WaitGroup
	wg.Add(6)

	go func() {
		defer wg.Done()
		setPredicateIfNotNil(p.ParsePolicyPredicate(data))
	}()
	go func() {
		defer wg.Done()
		setPredicateIfNotNil(p.ParsePolicySetPredicate(data))
	}()
	go func() {
		defer wg.Done()
		setPredicateIfNotNil(p.ParsePolicyGroupPredicate(data))
	}()
	go func() {
		defer wg.Done()
		setPredicateIfNotNil(p.ParseResultPredicate(data))
	}()
	go func() {
		defer wg.Done()
		setPredicateIfNotNil(p.ParseResultSetPredicate(data))
	}()
	go func() {
		defer wg.Done()
		setPredicateIfNotNil(p.ParseResultGroupPredicate(data))
	}()
	wg.Wait()

	if pred == nil {
		return nil, attestation.ErrNotCorrectFormat
	}
	return pred, nil
}

// PolicySet variant ===================

type ParserPolicySetPredicate struct{}

func NewParserPolicySetPredicate() *ParserPolicySetPredicate {
	return &ParserPolicySetPredicate{}
}

func (p *ParserPolicySetPredicate) Parse(data []byte) (attestation.Predicate, error) {
	return New().ParsePolicySetPredicate(data)
}

func (p *ParserPolicySetPredicate) SupportsType(predTypes ...attestation.PredicateType) bool {
	return slices.Contains(predTypes, PredicateTypePolicySet) ||
		slices.Contains(predTypes, PredicateTypePolicySet0)
}

func (p *Parser) ParsePolicySetPredicate(data []byte) (attestation.Predicate, error) {
	data, err := normalizeToJSON(data)
	if err != nil {
		return nil, err
	}
	set := &papi.PolicySet{}
	if err := protojson.Unmarshal(data, set); err != nil {
		if strings.Contains(err.Error(), "proto:") && strings.Contains(err.Error(), "unknown field") {
			return nil, attestation.ErrNotCorrectFormat
		}
		return nil, fmt.Errorf("unmarshaling predicate data: %w", err)
	}

	return &PolicySet{
		Parsed:       set,
		Data:         data,
		verification: nil,
	}, nil
}

// Policy variant ===================

type ParserPolicyPredicate struct{}

func NewParserPolicyPredicate() *ParserPolicyPredicate {
	return &ParserPolicyPredicate{}
}

func (p *ParserPolicyPredicate) Parse(data []byte) (attestation.Predicate, error) {
	return New().ParsePolicyPredicate(data)
}

func (p *ParserPolicyPredicate) SupportsType(predTypes ...attestation.PredicateType) bool {
	return slices.Contains(predTypes, PredicateTypePolicy) ||
		slices.Contains(predTypes, PredicateTypePolicy0)
}

func (p *Parser) ParsePolicyPredicate(data []byte) (attestation.Predicate, error) {
	data, err := normalizeToJSON(data)
	if err != nil {
		return nil, err
	}
	policy := &papi.Policy{}
	if err := protojson.Unmarshal(data, policy); err != nil {
		if strings.Contains(err.Error(), "proto:") && strings.Contains(err.Error(), "unknown field") {
			return nil, attestation.ErrNotCorrectFormat
		}
		return nil, fmt.Errorf("unmarshaling predicate data: %w", err)
	}
	return &Policy{
		Data:   data,
		Parsed: policy,
	}, nil
}

// PolicyGroup variant ===================

type ParserPolicyGroupPredicate struct{}

func NewParserPolicyGroupPredicate() *ParserPolicyGroupPredicate {
	return &ParserPolicyGroupPredicate{}
}

func (p *ParserPolicyGroupPredicate) Parse(data []byte) (attestation.Predicate, error) {
	return New().ParsePolicyGroupPredicate(data)
}

func (p *ParserPolicyGroupPredicate) SupportsType(predTypes ...attestation.PredicateType) bool {
	return slices.Contains(predTypes, PredicateTypePolicyGroup)
}

func (p *Parser) ParsePolicyGroupPredicate(data []byte) (attestation.Predicate, error) {
	data, err := normalizeToJSON(data)
	if err != nil {
		return nil, err
	}
	group := &papi.PolicyGroup{}
	if err := protojson.Unmarshal(data, group); err != nil {
		if strings.Contains(err.Error(), "proto:") && strings.Contains(err.Error(), "unknown field") {
			return nil, attestation.ErrNotCorrectFormat
		}
		return nil, fmt.Errorf("unmarshaling predicate data: %w", err)
	}
	return &PolicyGroup{
		Data:   data,
		Parsed: group,
	}, nil
}

// Result variant ===================

type ParserResultPredicate struct{}

func NewParserResultPredicate() *ParserResultPredicate {
	return &ParserResultPredicate{}
}

func (p *ParserResultPredicate) Parse(data []byte) (attestation.Predicate, error) {
	return New().ParseResultPredicate(data)
}

func (p *ParserResultPredicate) SupportsType(predTypes ...attestation.PredicateType) bool {
	return slices.Contains(predTypes, PredicateTypeResult) ||
		slices.Contains(predTypes, PredicateTypeResult0)
}

func (p *Parser) ParseResultPredicate(data []byte) (attestation.Predicate, error) {
	res := &papi.Result{}
	if err := protojson.Unmarshal(data, res); err != nil {
		if strings.Contains(err.Error(), "proto:") && strings.Contains(err.Error(), "unknown field") {
			return nil, attestation.ErrNotCorrectFormat
		}
		return nil, fmt.Errorf("unmarshaling predicate data: %w", err)
	}

	return &Result{
		Parsed: res,
		Data:   data,
	}, nil
}

// ResultSet variant ===================

type ParserResultSetPredicate struct{}

func NewParserResultSetPredicate() *ParserResultSetPredicate {
	return &ParserResultSetPredicate{}
}

func (p *ParserResultSetPredicate) Parse(data []byte) (attestation.Predicate, error) {
	return New().ParseResultSetPredicate(data)
}

func (p *ParserResultSetPredicate) SupportsType(predTypes ...attestation.PredicateType) bool {
	return slices.Contains(predTypes, PredicateTypeResultSet)
}

func (p *Parser) ParseResultSetPredicate(data []byte) (attestation.Predicate, error) {
	res := &papi.ResultSet{}
	if err := protojson.Unmarshal(data, res); err != nil {
		if strings.Contains(err.Error(), "proto:") && strings.Contains(err.Error(), "unknown field") {
			return nil, attestation.ErrNotCorrectFormat
		}
		return nil, fmt.Errorf("unmarshaling predicate data: %w", err)
	}

	return &ResultSet{
		Parsed: res,
		Data:   data,
	}, nil
}

// ResultGroup variant ===================

type ParserResultGroupPredicate struct{}

func NewParserResultGroupPredicate() *ParserResultGroupPredicate {
	return &ParserResultGroupPredicate{}
}

func (p *ParserResultGroupPredicate) Parse(data []byte) (attestation.Predicate, error) {
	return New().ParseResultGroupPredicate(data)
}

func (p *ParserResultGroupPredicate) SupportsType(predTypes ...attestation.PredicateType) bool {
	return slices.Contains(predTypes, PredicateTypeResultGroup)
}

func (p *Parser) ParseResultGroupPredicate(data []byte) (attestation.Predicate, error) {
	res := &papi.ResultGroup{}
	if err := protojson.Unmarshal(data, res); err != nil {
		if strings.Contains(err.Error(), "proto:") && strings.Contains(err.Error(), "unknown field") {
			return nil, attestation.ErrNotCorrectFormat
		}
		return nil, fmt.Errorf("unmarshaling predicate data: %w", err)
	}

	return &ResultGroup{
		Parsed: res,
		Data:   data,
	}, nil
}

func (*Parser) SupportsType(predTypes ...attestation.PredicateType) bool {
	for _, p := range PredicateTypes {
		if slices.Contains(predTypes, p) {
			return true
		}
	}
	return false
}
