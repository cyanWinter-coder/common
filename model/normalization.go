// Copyright 2026 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package model

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strconv"
	"strings"

	dto "github.com/prometheus/client_model/go"
)

// Label is one name/value pair. It is an alias of LabelPair so existing code
// that uses LabelPair values can pass those values to normalization APIs.
type Label = LabelPair

// Labels is a sorted, unique-by-canonical-name collection of labels.
//
// A zero Labels is empty and safe to fingerprint or format. Use NormalizeLabels
// or NewLabels to construct an instance that satisfies the guarantees.
type Labels []Label

// Conflict is a shorter alias for LabelConflict.
type Conflict = LabelConflict

// Conflicts is a shorter alias for LabelConflicts.
type Conflicts = LabelConflicts

// LabelConflict describes a repeated canonical label name or a collision while
// merging two label collections.
type LabelConflict struct {
	// Name is the canonical name shared by both labels.
	Name LabelName

	// ExistingName and IncomingName are the names exactly as supplied. They
	// differ from Name when case normalization makes two names collide.
	ExistingName LabelName
	IncomingName LabelName

	// ExistingValue is the value already present.
	ExistingValue LabelValue
	// IncomingValue is the value of the repeated or merged label.
	IncomingValue LabelValue

	// KeptValue is the value retained after applying the documented rule.
	KeptValue LabelValue

	// SameValue reports whether ExistingValue and IncomingValue are equal.
	SameValue bool
}

// Error implements error. A conflict report can therefore be returned or
// wrapped as an error when conflicts are not allowed.
func (c LabelConflict) Error() string {
	switch {
	case c.ExistingName != c.IncomingName && c.ExistingName != "" && c.IncomingName != "":
		if c.SameValue {
			return fmt.Sprintf("duplicate canonical label %q from names %q and %q with equal value %q",
				c.Name, c.ExistingName, c.IncomingName, c.KeptValue)
		}
		return fmt.Sprintf("conflicting canonical label %q from names %q and %q: value %q replaced by %q",
			c.Name, c.ExistingName, c.IncomingName, c.ExistingValue, c.IncomingValue)
	case c.SameValue:
		return fmt.Sprintf("duplicate label %q with equal value %q", c.Name, c.KeptValue)
	default:
		return fmt.Sprintf("conflicting label %q: value %q replaced by %q",
			c.Name, c.ExistingValue, c.IncomingValue)
	}
}

// LabelConflicts is the deterministic conflict report returned by normalization
// and merge operations.
type LabelConflicts []LabelConflict

// Error joins all conflict messages.
func (cs LabelConflicts) Error() string {
	if len(cs) == 0 {
		return "no label conflicts"
	}
	var b strings.Builder
	for i, c := range cs {
		if i > 0 {
			b.WriteString("; ")
		}
		b.WriteString(c.Error())
	}
	return b.String()
}

// AsError returns nil when there are no conflicts and otherwise returns the
// report as an error.
func (cs LabelConflicts) AsError() error {
	if len(cs) == 0 {
		return nil
	}
	return cs
}

// Unwrap enables errors.Is/As for an error wrapping the conflict report.
func (cs LabelConflicts) Unwrap() []error {
	errs := make([]error, len(cs))
	for i := range cs {
		errs[i] = cs[i]
	}
	return errs
}

var (
	// ErrInvalidLabel is the base error for label construction failures.
	ErrInvalidLabel = errors.New("invalid label")
	// ErrInvalidLabelName is returned when a label name is illegal.
	ErrInvalidLabelName = fmt.Errorf("%w name", ErrInvalidLabel)
	// ErrInvalidLabelValue is returned when a label value is illegal.
	ErrInvalidLabelValue = fmt.Errorf("%w value", ErrInvalidLabel)
	// ErrLabelConflict is returned by strict merge/normalization modes.
	ErrLabelConflict = errors.New("label conflict")
)

// InvalidLabelError identifies the exact label and field that failed validation.
type InvalidLabelError struct {
	// Name is the supplied label name. It is populated even when the name
	// itself is invalid.
	Name LabelName
	// Value is the supplied value.
	Value LabelValue
	// Field is either "name" or "value".
	Field string

	// Err optionally wraps the underlying parsing or validation failure.
	Err error
}

func (e *InvalidLabelError) Error() string {
	if e.Field == "value" {
		return fmt.Sprintf("invalid value %q for label %q", e.Value, e.Name)
	}
	return fmt.Sprintf("invalid name %q", e.Name)
}

// Unwrap exposes the field-specific and base validation sentinels.
func (e *InvalidLabelError) Unwrap() error {
	fieldErr := ErrInvalidLabelName
	if e.Field == "value" {
		fieldErr = ErrInvalidLabelValue
	}
	if e.Err != nil {
		return errors.Join(fieldErr, e.Err)
	}
	return fieldErr
}

// Is enables errors.Is(target, ErrLabelConflict) for conflict reports.
func (c LabelConflict) Is(target error) bool {
	return target == ErrLabelConflict
}

// Is enables errors.Is(report, ErrLabelConflict).
func (cs LabelConflicts) Is(target error) bool {
	return target == ErrLabelConflict
}

// CanonicalLabelName applies the fixed name identity rule: label names are
// compared and hashed case-insensitively and emitted in lower case.
//
// Illegal and invisible characters are not removed here; ValidateLabelName
// rejects them so bad exporter data is reported at the construction boundary.
func CanonicalLabelName(name LabelName) LabelName {
	return LabelName(strings.ToLower(string(name)))
}

// ValidateLabelName validates a name using the active NameValidationScheme and
// the fixed no-invisible-character rule used by normalized label sets.
func ValidateLabelName(name LabelName) error {
	scheme := NameValidationScheme
	if scheme == UnsetValidation {
		scheme = UTF8Validation
	}
	return validateLabelName(name, scheme)
}

func validateLabelName(name LabelName, scheme ValidationScheme) error {
	if !scheme.IsValidLabelName(string(name)) {
		return &InvalidLabelError{Name: name, Field: "name"}
	}
	for _, r := range string(name) {
		if !strconv.IsPrint(r) {
			return &InvalidLabelError{Name: name, Field: "name"}
		}
	}
	return nil
}

// ValidateLabelValue validates a label value. Empty values are legal.
func ValidateLabelValue(name LabelName, value LabelValue) error {
	if !value.IsValid() {
		return &InvalidLabelError{Name: name, Value: value, Field: "value"}
	}
	return nil
}

// NormalizeOption customizes the small number of normalization boundaries that
// must interoperate with existing validation schemes. Most callers should use
// NormalizeLabels directly.
type NormalizeOption func(*normalizeConfig)

type normalizeConfig struct {
	scheme          ValidationScheme
	canonicalCase   bool
	rejectInvisible bool
}

// WithValidationScheme validates names with scheme instead of
// NameValidationScheme.
func WithValidationScheme(scheme ValidationScheme) NormalizeOption {
	return func(cfg *normalizeConfig) { cfg.scheme = scheme }
}

// WithCaseCanonicalization controls lower-casing of names. It is enabled by
// default to prevent exporter case variants from splitting one series.
func WithCaseCanonicalization(enabled bool) NormalizeOption {
	return func(cfg *normalizeConfig) { cfg.canonicalCase = enabled }
}

// WithInvisibleCharacterRejection controls the strict invisible-character rule.
// It is enabled by default.
func WithInvisibleCharacterRejection(enabled bool) NormalizeOption {
	return func(cfg *normalizeConfig) { cfg.rejectInvisible = enabled }
}

func defaultNormalizeConfig() normalizeConfig {
	scheme := NameValidationScheme
	if scheme == UnsetValidation {
		scheme = UTF8Validation
	}
	return normalizeConfig{scheme: scheme, canonicalCase: true, rejectInvisible: true}
}

// NormalizeLabels is the compatibility entry point for normalization. It
// accepts the common label representations in this repository and exporter
// DTOs: []LabelPair/Labels, LabelPairs, LabelSet/Metric, ordinary maps,
// alternating strings, and dto.LabelPair values. Multiple inputs are processed
// in argument order, which is useful when normalizing a remote-write merge in
// one call. NormalizeOption values configure validation.
//
// Most callers with a statically known []LabelPair can use NormalizeLabelPairs
// directly.
func NormalizeLabels(args ...any) (Labels, LabelConflicts, error) {
	cfg := defaultNormalizeConfig()
	pairs := make([]LabelPair, 0)
	var stringsAsPairs []string

	for _, arg := range args {
		switch a := arg.(type) {
		case NormalizeOption:
			a(&cfg)
		case ValidationScheme:
			WithValidationScheme(a)(&cfg)
		case bool:
			// Compatibility for callers using a positional
			// case-normalization boolean.
			WithCaseCanonicalization(a)(&cfg)
		case nil:
			continue
		case string:
			stringsAsPairs = append(stringsAsPairs, a)
		default:
			collected, err := collectLabelPairs(a)
			if err != nil {
				return nil, nil, err
			}
			pairs = append(pairs, collected...)
		}
	}

	if len(stringsAsPairs) > 0 {
		collected, err := stringPairs(stringsAsPairs)
		if err != nil {
			return nil, nil, err
		}
		pairs = append(pairs, collected...)
	}
	return normalizeLabelPairs(pairs, cfg)
}

// NormalizePairSlice is the strongly typed option-aware form of
// NormalizeLabels for []LabelPair.
func NormalizePairSlice(pairs []LabelPair, opts ...NormalizeOption) (Labels, LabelConflicts, error) {
	cfg := defaultNormalizeConfig()
	for _, opt := range opts {
		opt(&cfg)
	}
	return normalizeLabelPairs(pairs, cfg)
}

func normalizeLabelPairs(pairs []LabelPair, cfg normalizeConfig) (Labels, LabelConflicts, error) {
	out := make(Labels, 0, len(pairs))
	originalNames := make([]LabelName, 0, len(pairs))
	index := make(map[LabelName]int, len(pairs))
	var conflicts LabelConflicts

	for _, pair := range pairs {
		name := pair.Name
		if err := validateWithConfig(name, pair.Value, cfg); err != nil {
			return nil, nil, err
		}
		canonical := name
		if cfg.canonicalCase {
			canonical = CanonicalLabelName(name)
		}

		if i, ok := index[canonical]; ok {
			previous := out[i]
			conflicts = append(conflicts, LabelConflict{
				Name:          canonical,
				ExistingName:  originalNames[i],
				IncomingName:  name,
				ExistingValue: previous.Value,
				IncomingValue: pair.Value,
				KeptValue:     pair.Value,
				SameValue:     previous.Value == pair.Value,
			})
			out[i] = Label{Name: canonical, Value: pair.Value}
			originalNames[i] = name
			continue
		}

		index[canonical] = len(out)
		out = append(out, Label{Name: canonical, Value: pair.Value})
		originalNames = append(originalNames, name)
	}

	slices.SortFunc(out, func(a, b Label) int {
		return strings.Compare(string(a.Name), string(b.Name))
	})
	return out, conflicts, nil
}

func validateWithConfig(name LabelName, value LabelValue, cfg normalizeConfig) error {
	if !cfg.scheme.IsValidLabelName(string(name)) {
		return &InvalidLabelError{Name: name, Value: value, Field: "name"}
	}
	if cfg.rejectInvisible {
		for _, r := range string(name) {
			if !strconv.IsPrint(r) {
				return &InvalidLabelError{Name: name, Value: value, Field: "name"}
			}
		}
	}
	if !value.IsValid() {
		return &InvalidLabelError{Name: name, Value: value, Field: "value"}
	}
	return nil
}

// NewLabels is a variadic constructor equivalent to NormalizeLabels.
func NewLabels(pairs ...LabelPair) (Labels, LabelConflicts, error) {
	return NormalizeLabels(pairs)
}

// Normalize is the LabelPairs method form of NormalizeLabelPairs.
func (pairs LabelPairs) Normalize(opts ...NormalizeOption) (Labels, LabelConflicts, error) {
	return NormalizeLabelPairs(pairs, opts...)
}

// NewLabelSet constructs a validated, canonical LabelSet from ordered pairs.
// Pair order determines the last value retained for a duplicate.
func NewLabelSet(pairs ...LabelPair) (LabelSet, LabelConflicts, error) {
	labels, conflicts, err := NormalizeLabels(pairs)
	if err != nil {
		return nil, nil, err
	}
	return labels.LabelSet(), conflicts, nil
}

// NewNormalizedLabelSet is an alias for NewLabelSet.
func NewNormalizedLabelSet(pairs ...LabelPair) (LabelSet, LabelConflicts, error) {
	return NewLabelSet(pairs...)
}

// LabelsFromMap converts a map to sorted Labels. Because Go maps have no
// insertion order, raw names are sorted and the lexicographically later raw
// name wins when case/invisible canonicalization creates a collision.
func LabelsFromMap[S ~map[K]V, K ~string, V ~string](m S) (Labels, LabelConflicts, error) {
	names := make([]K, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	slices.Sort(names)

	pairs := make([]LabelPair, 0, len(names))
	for _, name := range names {
		pairs = append(pairs, LabelPair{Name: LabelName(name), Value: LabelValue(m[name])})
	}
	return NormalizeLabels(pairs)
}

// LabelsFromStrings builds normalized Labels from alternating name/value
// strings, matching the common Prometheus labels.FromStrings construction
// style.
func LabelsFromStrings(keysAndValues ...string) (Labels, LabelConflicts, error) {
	if len(keysAndValues)%2 != 0 {
		return nil, nil, fmt.Errorf("odd number of label key/value strings: %d", len(keysAndValues))
	}
	pairs := make([]LabelPair, 0, len(keysAndValues)/2)
	for i := 0; i < len(keysAndValues); i += 2 {
		pairs = append(pairs, LabelPair{
			Name:  LabelName(keysAndValues[i]),
			Value: LabelValue(keysAndValues[i+1]),
		})
	}
	return NormalizeLabels(pairs)
}

// NormalizeLabelSet validates and canonicalizes an existing LabelSet. The
// returned set is independent of ls. Raw names are sorted before processing so
// canonical collisions have deterministic last-write semantics.
func NormalizeLabelSet(ls LabelSet, opts ...NormalizeOption) (LabelSet, LabelConflicts, error) {
	names := make(LabelNames, 0, len(ls))
	for name := range ls {
		names = append(names, name)
	}
	slices.Sort(names)

	pairs := make([]LabelPair, 0, len(names))
	for _, name := range names {
		pairs = append(pairs, LabelPair{Name: name, Value: ls[name]})
	}
	labels, conflicts, err := NormalizePairSlice(pairs, opts...)
	if err != nil {
		return nil, nil, err
	}
	return labels.LabelSet(), conflicts, nil
}

// CanonicalizeLabels is an alias for NormalizeLabels.
func CanonicalizeLabels(pairs []LabelPair, opts ...NormalizeOption) (Labels, LabelConflicts, error) {
	return NormalizePairSlice(pairs, opts...)
}

// CanonicalizeLabelSet is an alias for NormalizeLabelSet.
func CanonicalizeLabelSet(ls LabelSet, opts ...NormalizeOption) (LabelSet, LabelConflicts, error) {
	return NormalizeLabelSet(ls, opts...)
}

// Normalize is the method form of NormalizeLabelSet.
func (ls LabelSet) Normalize(opts ...NormalizeOption) (LabelSet, LabelConflicts, error) {
	return NormalizeLabelSet(ls, opts...)
}

// LabelSet returns the LabelSet representation of normalized Labels.
func (ls Labels) LabelSet() LabelSet {
	out := make(LabelSet, len(ls))
	for _, label := range ls {
		out[label.Name] = label.Value
	}
	return out
}

// Get returns the value for name and whether it was present. The name is
// canonicalized before lookup.
func (ls Labels) Get(name LabelName) (LabelValue, bool) {
	compare := func(l Label, target Label) int {
		return strings.Compare(string(l.Name), string(target.Name))
	}
	if i, found := slices.BinarySearchFunc(ls, Label{Name: name}, compare); found {
		return ls[i].Value, true
	}
	canonical := CanonicalLabelName(name)
	if canonical == name {
		return "", false
	}
	if i, found := slices.BinarySearchFunc(ls, Label{Name: canonical}, compare); found {
		return ls[i].Value, true
	}
	return "", false
}

// Has reports whether the canonical name is present.
func (ls Labels) Has(name LabelName) bool {
	_, ok := ls.Get(name)
	return ok
}

// Clone returns an independent copy.
func (ls Labels) Clone() Labels {
	return slices.Clone(ls)
}

// Validate verifies that normalized Labels are canonical, sorted and unique.
func (ls Labels) Validate() error {
	var previous LabelName
	for i, label := range ls {
		if err := ValidateLabelName(label.Name); err != nil {
			return err
		}
		if err := ValidateLabelValue(label.Name, label.Value); err != nil {
			return err
		}
		canonical := CanonicalLabelName(label.Name)
		if label.Name != canonical {
			return fmt.Errorf("label %q is not canonical; expected %q", label.Name, canonical)
		}
		if i > 0 && canonical <= previous {
			return fmt.Errorf("labels are not sorted and unique at %q", label.Name)
		}
		previous = canonical
	}
	return nil
}

// Len implements sort.Interface.
func (ls Labels) Len() int { return len(ls) }

// Less implements sort.Interface.
func (ls Labels) Less(i, j int) bool { return ls[i].Name < ls[j].Name }

// Swap implements sort.Interface.
func (ls Labels) Swap(i, j int) { ls[i], ls[j] = ls[j], ls[i] }

// String formats Labels like LabelSet.String.
func (ls Labels) String() string {
	var b bytes.Buffer
	var quoteBuf [1024]byte
	b.WriteByte('{')
	for i, label := range ls {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(string(label.Name))
		b.WriteByte('=')
		b.Write(strconv.AppendQuote(quoteBuf[:0], string(label.Value)))
	}
	b.WriteByte('}')
	return b.String()
}

// Fingerprint returns the same stable FNV-1a fingerprint as the equivalent
// LabelSet. The hash input is sorted by construction and does not depend on
// map iteration, process, or restart.
func (ls Labels) Fingerprint() Fingerprint {
	if len(ls) == 0 {
		return Fingerprint(emptyLabelSignature)
	}
	sum := hashNew()
	for _, label := range ls {
		sum = hashAdd(sum, string(label.Name))
		sum = hashAddByte(sum, SeparatorByte)
		sum = hashAdd(sum, string(label.Value))
		sum = hashAddByte(sum, SeparatorByte)
	}
	return Fingerprint(sum)
}

// MergeStrategy determines how value collisions are resolved.
type MergeStrategy int

const (
	// MergeReject returns a *LabelConflictError when names have different
	// values. Equal duplicates are not conflicts.
	MergeReject MergeStrategy = iota
	// MergeKeepExisting keeps the value from the first collection.
	MergeKeepExisting
	// MergeKeepIncoming keeps the value from the second collection. This is
	// the explicit last-writer-wins rule.
	MergeKeepIncoming
)

// LabelConflictError wraps all merge conflicts when MergeReject is used.
type LabelConflictError struct {
	Conflicts LabelConflicts
}

func (e *LabelConflictError) Error() string {
	return "label merge conflict: " + e.Conflicts.Error()
}

// Unwrap returns the conflict report.
func (e *LabelConflictError) Unwrap() error { return e.Conflicts }

// MergeLabels merges two normalized, sorted label collections in linear time.
// The default strategy is MergeKeepIncoming. Different values are reported;
// equal duplicates are merged without a conflict.
func MergeLabels(existing, incoming Labels, strategies ...MergeStrategy) (Labels, LabelConflicts, error) {
	strategy := MergeKeepIncoming
	if len(strategies) > 0 {
		strategy = strategies[len(strategies)-1]
	}
	if strategy != MergeReject && strategy != MergeKeepExisting && strategy != MergeKeepIncoming {
		return nil, nil, fmt.Errorf("unknown label merge strategy %d", strategy)
	}

	// Also accept labels built literally or decoded from exporter DTOs.
	// Normalizing here makes case variants and in-slice duplicates impossible
	// to merge into two canonical entries.
	existing, existingConflicts, err := NormalizePairSlice([]LabelPair(existing))
	if err != nil {
		return nil, nil, err
	}
	incoming, incomingConflicts, err := NormalizePairSlice([]LabelPair(incoming))
	if err != nil {
		return nil, nil, err
	}
	inputConflicts := slices.Concat(existingConflicts, incomingConflicts)

	out := make(Labels, 0, len(existing)+len(incoming))
	var conflicts LabelConflicts
	i, j := 0, 0
	for i < len(existing) || j < len(incoming) {
		switch {
		case j == len(incoming) || (i < len(existing) && existing[i].Name < incoming[j].Name):
			out = append(out, existing[i])
			i++
		case i == len(existing) || existing[i].Name > incoming[j].Name:
			out = append(out, incoming[j])
			j++
		default:
			a, b := existing[i], incoming[j]
			conflict := LabelConflict{
				Name:          a.Name,
				ExistingName:  a.Name,
				IncomingName:  b.Name,
				ExistingValue: a.Value,
				IncomingValue: b.Value,
				SameValue:     a.Value == b.Value,
			}
			switch {
			case conflict.SameValue:
				conflict.KeptValue = a.Value
			case strategy == MergeKeepExisting:
				conflict.KeptValue = a.Value
				conflicts = append(conflicts, conflict)
			case strategy == MergeKeepIncoming:
				conflict.KeptValue = b.Value
				conflicts = append(conflicts, conflict)
			default:
				conflicts = append(conflicts, conflict)
			}
			out = append(out, Label{Name: a.Name, Value: conflict.KeptValue})
			i++
			j++
		}
	}

	allConflicts := slices.Concat(inputConflicts, conflicts)
	if strategy == MergeReject && len(conflicts) > 0 {
		return nil, allConflicts, &LabelConflictError{Conflicts: slices.Clone(conflicts)}
	}
	return out, allConflicts, nil
}

// MergeLabelSets merges two maps using the same explicit rules as MergeLabels.
// Both inputs are canonicalized first.
func MergeLabelSets(existing, incoming LabelSet, strategies ...MergeStrategy) (LabelSet, LabelConflicts, error) {
	a, aConflicts, err := LabelsFromMap(existing)
	if err != nil {
		return nil, nil, err
	}
	b, bConflicts, err := LabelsFromMap(incoming)
	if err != nil {
		return nil, nil, err
	}
	strategy := MergeKeepIncoming
	if len(strategies) > 0 {
		strategy = strategies[len(strategies)-1]
	}
	merged, mergeConflicts, err := MergeLabels(a, b, strategy)
	allConflicts := slices.Concat(aConflicts, bConflicts, mergeConflicts)
	if err != nil {
		return nil, allConflicts, err
	}
	return merged.LabelSet(), allConflicts, nil
}

// MergeChecked is a strict LabelSet merge: different values cause an error.
func (ls LabelSet) MergeChecked(other LabelSet) (LabelSet, error) {
	merged, conflicts, err := MergeLabelSets(ls, other, MergeReject)
	if err != nil {
		return nil, err
	}
	_ = conflicts
	return merged, nil
}

// MergeWithConflicts is last-writer-wins for other and returns every value
// collision instead of silently overwriting it.
func (ls LabelSet) MergeWithConflicts(other LabelSet) (LabelSet, LabelConflicts, error) {
	return MergeLabelSets(ls, other, MergeKeepIncoming)
}

func stringPairs(values []string) ([]LabelPair, error) {
	if len(values)%2 != 0 {
		return nil, fmt.Errorf("odd number of label key/value strings: %d", len(values))
	}
	pairs := make([]LabelPair, 0, len(values)/2)
	for i := 0; i < len(values); i += 2 {
		pairs = append(pairs, LabelPair{Name: LabelName(values[i]), Value: LabelValue(values[i+1])})
	}
	return pairs, nil
}

func collectLabelPairs(input any) ([]LabelPair, error) {
	switch x := input.(type) {
	case LabelPair:
		return []LabelPair{x}, nil
	case *LabelPair:
		if x == nil {
			return nil, fmt.Errorf("invalid label: nil *LabelPair")
		}
		return []LabelPair{*x}, nil
	case Labels:
		return []LabelPair(x), nil
	case []LabelPair:
		return x, nil
	case LabelPairs:
		out := make([]LabelPair, 0, len(x))
		for i, pair := range x {
			if pair == nil {
				return nil, fmt.Errorf("invalid label at index %d: nil label pair", i)
			}
			out = append(out, *pair)
		}
		return out, nil
	case []*LabelPair:
		out := make([]LabelPair, 0, len(x))
		for i, pair := range x {
			if pair == nil {
				return nil, fmt.Errorf("invalid label at index %d: nil label pair", i)
			}
			out = append(out, *pair)
		}
		return out, nil
	case LabelSet:
		return labelSetPairs(x), nil
	case Metric:
		return labelSetPairs(LabelSet(x)), nil
	case dto.LabelPair:
		return []LabelPair{{Name: LabelName(x.GetName()), Value: LabelValue(x.GetValue())}}, nil
	case *dto.LabelPair:
		if x == nil {
			return nil, fmt.Errorf("invalid label: nil *dto.LabelPair")
		}
		return []LabelPair{{Name: LabelName(x.GetName()), Value: LabelValue(x.GetValue())}}, nil
	case []dto.LabelPair:
		out := make([]LabelPair, 0, len(x))
		for i := range x {
			out = append(out, LabelPair{Name: LabelName(x[i].GetName()), Value: LabelValue(x[i].GetValue())})
		}
		return out, nil
	case []*dto.LabelPair:
		out := make([]LabelPair, 0, len(x))
		for i, pair := range x {
			if pair == nil {
				return nil, fmt.Errorf("invalid label at index %d: nil dto.LabelPair", i)
			}
			out = append(out, LabelPair{Name: LabelName(pair.GetName()), Value: LabelValue(pair.GetValue())})
		}
		return out, nil
	case []string:
		return stringPairs(x)
	}

	rv := reflect.ValueOf(input)
	if !rv.IsValid() {
		return nil, nil
	}
	for rv.Kind() == reflect.Interface || rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			return nil, nil
		}
		rv = rv.Elem()
	}

	switch rv.Kind() {
	case reflect.Map:
		return reflectMapPairs(rv)
	case reflect.Slice, reflect.Array:
		return reflectSlicePairs(rv)
	case reflect.Struct:
		pair, ok := reflectStructPair(rv)
		if !ok {
			return nil, fmt.Errorf("unsupported label struct type %T", input)
		}
		return []LabelPair{pair}, nil
	default:
		return nil, fmt.Errorf("unsupported label collection type %T", input)
	}
}

func NormalizeLabelPairs(pairs LabelPairs, opts ...NormalizeOption) (Labels, LabelConflicts, error) {
	values := make([]LabelPair, 0, len(pairs))
	for i, pair := range pairs {
		if pair == nil {
			return nil, nil, fmt.Errorf("invalid label at index %d: nil label pair", i)
		}
		values = append(values, *pair)
	}
	return NormalizePairSlice(values, opts...)
}

func labelSetPairs(ls LabelSet) []LabelPair {
	names := make(LabelNames, 0, len(ls))
	for name := range ls {
		names = append(names, name)
	}
	slices.Sort(names)
	pairs := make([]LabelPair, 0, len(names))
	for _, name := range names {
		pairs = append(pairs, LabelPair{Name: name, Value: ls[name]})
	}
	return pairs
}

func reflectMapPairs(rv reflect.Value) ([]LabelPair, error) {
	keys := rv.MapKeys()
	slices.SortFunc(keys, func(a, b reflect.Value) int {
		return strings.Compare(a.String(), b.String())
	})
	pairs := make([]LabelPair, 0, len(keys))
	for _, key := range keys {
		if key.Kind() != reflect.String {
			return nil, fmt.Errorf("unsupported label name type %s", key.Type())
		}
		value, err := reflectLabelValue(rv.MapIndex(key))
		if err != nil {
			return nil, fmt.Errorf("label %q: %w", key.String(), err)
		}
		pairs = append(pairs, LabelPair{Name: LabelName(key.String()), Value: value})
	}
	return pairs, nil
}

func reflectSlicePairs(rv reflect.Value) ([]LabelPair, error) {
	// Named string slices and []any containing only strings use the common
	// alternating key/value construction.
	allStrings := rv.Len() > 0
	stringValues := make([]string, rv.Len())
	for i := 0; i < rv.Len(); i++ {
		v, err := reflectLabelValue(rv.Index(i))
		if err != nil {
			allStrings = false
			break
		}
		if rv.Index(i).Kind() == reflect.String || (rv.Index(i).Kind() == reflect.Interface && rv.Index(i).Elem().Kind() == reflect.String) {
			stringValues[i] = string(v)
			continue
		}
		allStrings = false
		break
	}
	if allStrings {
		return stringPairs(stringValues)
	}

	pairs := make([]LabelPair, 0, rv.Len())
	for i := 0; i < rv.Len(); i++ {
		ev := rv.Index(i)
		for ev.Kind() == reflect.Interface || ev.Kind() == reflect.Pointer {
			if ev.IsNil() {
				return nil, fmt.Errorf("invalid label at index %d: nil label pair", i)
			}
			ev = ev.Elem()
		}
		pair, ok := reflectStructPair(ev)
		if !ok {
			return nil, fmt.Errorf("unsupported label element type %s at index %d", ev.Type(), i)
		}
		pairs = append(pairs, pair)
	}
	return pairs, nil
}

func reflectStructPair(rv reflect.Value) (LabelPair, bool) {
	if rv.CanInterface() {
		type nameGetter interface{ GetName() string }
		type valueGetter interface{ GetValue() string }
		ng, okName := rv.Interface().(nameGetter)
		vg, okValue := rv.Interface().(valueGetter)
		if okName && okValue {
			return LabelPair{Name: LabelName(ng.GetName()), Value: LabelValue(vg.GetValue())}, true
		}
	}

	nameField := rv.FieldByName("Name")
	valueField := rv.FieldByName("Value")
	if !nameField.IsValid() || !valueField.IsValid() || nameField.Kind() != reflect.String || valueField.Kind() != reflect.String {
		return LabelPair{}, false
	}
	return LabelPair{Name: LabelName(nameField.String()), Value: LabelValue(valueField.String())}, true
}

func reflectLabelValue(rv reflect.Value) (LabelValue, error) {
	for rv.IsValid() && (rv.Kind() == reflect.Interface || rv.Kind() == reflect.Pointer) {
		if rv.IsNil() {
			return "", nil
		}
		rv = rv.Elem()
	}
	if !rv.IsValid() {
		return "", nil
	}
	if rv.Kind() == reflect.String {
		return LabelValue(rv.String()), nil
	}
	if rv.CanInterface() {
		switch v := rv.Interface().(type) {
		case nil:
			return "", nil
		case fmt.Stringer:
			return LabelValue(v.String()), nil
		}
	}
	return "", fmt.Errorf("unsupported label value type %s", rv.Type())
}

// NormalizeValue converts exporter null representations to the stable empty
// label value. Nil pointers and untyped nil become "".
func NormalizeValue(value any) (LabelValue, error) {
	switch v := value.(type) {
	case nil:
		return "", nil
	case string:
		lv := LabelValue(v)
		return lv, ValidateLabelValue("", lv)
	case LabelValue:
		return v, ValidateLabelValue("", v)
	case LabelName:
		lv := LabelValue(v)
		return lv, ValidateLabelValue("", lv)
	case *string:
		if v == nil {
			return "", nil
		}
		return NormalizeValue(*v)
	case *LabelValue:
		if v == nil {
			return "", nil
		}
		return NormalizeValue(string(*v))
	case *LabelName:
		if v == nil {
			return "", nil
		}
		return NormalizeValue(string(*v))
	case json.RawMessage:
		trimmed := bytes.TrimSpace(v)
		if string(trimmed) == "null" {
			return "", nil
		}
		var s string
		if err := json.Unmarshal(trimmed, &s); err != nil {
			return "", fmt.Errorf("invalid label value JSON %s: %w", string(trimmed), err)
		}
		return NormalizeValue(s)
	default:
		return "", fmt.Errorf("unsupported label value type %T", value)
	}
}

// NormalizeLabelValue is a descriptive alias for NormalizeValue.
func NormalizeLabelValue(value any) (LabelValue, error) {
	return NormalizeValue(value)
}

// NormalizeLabelSetJSON decodes a JSON object and normalizes it. Unlike ordinary
// map unmarshalling, it sees duplicate JSON keys. JSON null values normalize to
// empty strings.
func NormalizeLabelSetJSON(data []byte, opts ...NormalizeOption) (Labels, LabelConflicts, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return nil, nil, fmt.Errorf("decode label set: %w", err)
	}
	delim, ok := tok.(json.Delim)
	if !ok || delim != '{' {
		return nil, nil, fmt.Errorf("decode label set: expected JSON object, got %v", tok)
	}

	var pairs []LabelPair
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, nil, fmt.Errorf("decode label name: %w", err)
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil, nil, fmt.Errorf("decode label name: expected string, got %T", keyTok)
		}

		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, nil, fmt.Errorf("decode value for label %q: %w", key, err)
		}
		value, err := NormalizeValue(raw)
		if err != nil {
			return nil, nil, &InvalidLabelError{Name: LabelName(key), Field: "value", Err: err}
		}
		pairs = append(pairs, LabelPair{Name: LabelName(key), Value: value})
	}
	if _, err := dec.Token(); err != nil {
		return nil, nil, fmt.Errorf("decode label set end: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			return nil, nil, fmt.Errorf("decode label set: unexpected trailing JSON value")
		}
		return nil, nil, fmt.Errorf("decode label set trailing data: %w", err)
	}
	return NormalizePairSlice(pairs, opts...)
}
