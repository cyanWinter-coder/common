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
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	dto "github.com/prometheus/client_model/go"
)

func TestUID595NormalizeLabelsSortsDeduplicatesAndReportsConflict(t *testing.T) {
	pairs := []LabelPair{
		{Name: "z", Value: "last-z"},
		{Name: "a", Value: "first"},
		{Name: "a", Value: "last"},
		{Name: "same", Value: "v"},
		{Name: "same", Value: "v"},
	}

	got, conflicts, err := NormalizeLabels(pairs)
	if err != nil {
		t.Fatalf("NormalizeLabels returned unexpected error: %v", err)
	}

	want := Labels{
		{Name: "a", Value: "last"},
		{Name: "same", Value: "v"},
		{Name: "z", Value: "last-z"},
	}
	if !uid595LabelsEqual(got, want) {
		t.Fatalf("normalized labels = %v, want %v", got, want)
	}
	if len(conflicts) != 2 {
		t.Fatalf("len(conflicts) = %d, want 2: %v", len(conflicts), conflicts)
	}
	if conflicts[0].Name != "a" || conflicts[0].ExistingValue != "first" ||
		conflicts[0].IncomingValue != "last" || conflicts[0].KeptValue != "last" ||
		conflicts[0].SameValue {
		t.Fatalf("unexpected value conflict: %+v", conflicts[0])
	}
	if conflicts[1].Name != "same" || !conflicts[1].SameValue || conflicts[1].KeptValue != "v" {
		t.Fatalf("unexpected equal duplicate conflict: %+v", conflicts[1])
	}
}

func TestUID595NormalizeLabelsCanonicalizesCase(t *testing.T) {
	got, conflicts, err := NormalizeLabels([]LabelPair{
		{Name: "Job", Value: "api"},
		{Name: "JOB", Value: "worker"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "job" || got[0].Value != "worker" {
		t.Fatalf("unexpected normalized labels: %v", got)
	}
	if len(conflicts) != 1 || conflicts[0].ExistingName != "Job" || conflicts[0].IncomingName != "JOB" {
		t.Fatalf("unexpected case conflict: %+v", conflicts)
	}
}

func TestUID595NormalizeLabelsRejectsInvalidNameWithLabel(t *testing.T) {
	oldScheme := NameValidationScheme
	NameValidationScheme = LegacyValidation
	t.Cleanup(func() { NameValidationScheme = oldScheme })

	_, _, err := NormalizeLabels([]LabelPair{{Name: "1invalid", Value: "x"}})
	var invalid *InvalidLabelError
	if !errors.As(err, &invalid) {
		t.Fatalf("expected *InvalidLabelError, got %T: %v", err, err)
	}
	if invalid.Name != "1invalid" || invalid.Field != "name" {
		t.Fatalf("error does not identify label name: %+v", invalid)
	}
	if !errors.Is(err, ErrInvalidLabelName) {
		t.Fatalf("error %v does not wrap ErrInvalidLabelName", err)
	}
	if !strings.Contains(err.Error(), `"1invalid"`) {
		t.Fatalf("error %q does not contain label name", err)
	}
}

func TestUID595NormalizeLabelsRejectsInvisibleName(t *testing.T) {
	for _, name := range []LabelName{"bad\tname", "bad​name", "bad\x00name"} {
		t.Run(string(name), func(t *testing.T) {
			_, _, err := NormalizeLabels([]LabelPair{{Name: name, Value: "x"}})
			if err == nil {
				t.Fatal("expected invisible character name to be rejected")
			}
			var invalid *InvalidLabelError
			if !errors.As(err, &invalid) || invalid.Name != name {
				t.Fatalf("expected error identifying %q, got %v", name, err)
			}
		})
	}
}

func TestUID595NormalizeLabelsAllowsPrintableUTF8Space(t *testing.T) {
	oldScheme := NameValidationScheme
	NameValidationScheme = UTF8Validation
	t.Cleanup(func() { NameValidationScheme = oldScheme })

	got, _, err := NormalizeLabels([]LabelPair{{Name: "label name", Value: "x"}})
	if err != nil {
		t.Fatalf("printable UTF-8 label name rejected: %v", err)
	}
	if len(got) != 1 || got[0].Name != "label name" {
		t.Fatalf("unexpected labels: %v", got)
	}
}

func TestUID595NormalizeLabelsRejectsInvalidValueWithLabel(t *testing.T) {
	_, _, err := NormalizeLabels([]LabelPair{{Name: "region", Value: "bad\xffvalue"}})
	var invalid *InvalidLabelError
	if !errors.As(err, &invalid) {
		t.Fatalf("expected *InvalidLabelError, got %T: %v", err, err)
	}
	if invalid.Name != "region" || invalid.Field != "value" {
		t.Fatalf("error does not identify label: %+v", invalid)
	}
	if !errors.Is(err, ErrInvalidLabelValue) {
		t.Fatalf("error %v does not wrap ErrInvalidLabelValue", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, `"region"`) || !strings.Contains(msg, "invalid value") {
		t.Fatalf("error %q does not identify label and value failure", msg)
	}
}

func TestUID595NormalizedFingerprintIsStable(t *testing.T) {
	pairs := []LabelPair{
		{Name: "z", Value: "z-value"},
		{Name: "a", Value: "a-value"},
		{Name: "__name__", Value: "metric_total"},
		{Name: "a", Value: "a-value"},
	}
	labels, _, err := NormalizeLabels(pairs)
	if err != nil {
		t.Fatal(err)
	}
	set := labels.LabelSet()

	if got, want := labels.Fingerprint(), set.Fingerprint(); got != want {
		t.Fatalf("Labels.Fingerprint() = %v, LabelSet fingerprint = %v", got, want)
	}
	if labels.Fingerprint() != labels.Fingerprint() {
		t.Fatal("fingerprint is not stable on repeated calls")
	}

	// A separately constructed set with the same canonical content must hash
	// identically regardless of construction/order.
	other, _, err := NormalizeLabelSet(LabelSet{
		"__name__": "metric_total",
		"a":        "a-value",
		"z":        "z-value",
	})
	if err != nil {
		t.Fatal(err)
	}
	if labels.Fingerprint() != other.Fingerprint() {
		t.Fatalf("fingerprints differ: %v vs %v", labels.Fingerprint(), other.Fingerprint())
	}
}

func TestUID595EmptyAndReservedLabelSetsAreStable(t *testing.T) {
	empty, conflicts, err := NormalizeLabels(nil)
	if err != nil || len(conflicts) != 0 {
		t.Fatalf("empty normalization failed: labels=%v conflicts=%v err=%v", empty, conflicts, err)
	}
	if empty.Fingerprint() != Fingerprint(emptyLabelSignature) {
		t.Fatalf("empty fingerprint = %v, want %v", empty.Fingerprint(), Fingerprint(emptyLabelSignature))
	}
	if empty.Fingerprint() != LabelSet(nil).Fingerprint() {
		t.Fatal("empty Labels and nil LabelSet fingerprints differ")
	}
	if empty.String() != "{}" {
		t.Fatalf("empty.String() = %q, want {}", empty.String())
	}

	reserved, _, err := NormalizeLabels([]LabelPair{{Name: MetricNameLabel, Value: "up"}})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := reserved.Get(MetricNameLabel); !ok || got != "up" {
		t.Fatalf("reserved label not preserved: %v ok=%v", got, ok)
	}
	wantSet := LabelSet{MetricNameLabel: "up"}
	if reserved.Fingerprint() != wantSet.Fingerprint() {
		t.Fatal("reserved-only fingerprint differs from equivalent LabelSet")
	}
}

func TestUID595MergeLabelsConflictRules(t *testing.T) {
	a := Labels{{Name: "a", Value: "1"}, {Name: "shared", Value: "old"}}
	b := Labels{{Name: "shared", Value: "new"}, {Name: "b", Value: "2"}}

	t.Run("incoming wins with report", func(t *testing.T) {
		got, conflicts, err := MergeLabels(a, b)
		if err != nil {
			t.Fatal(err)
		}
		want := Labels{
			{Name: "a", Value: "1"},
			{Name: "b", Value: "2"},
			{Name: "shared", Value: "new"},
		}
		if !uid595LabelsEqual(got, want) {
			t.Fatalf("merge = %v, want %v", got, want)
		}
		if len(conflicts) != 1 || conflicts[0].Name != "shared" || conflicts[0].KeptValue != "new" {
			t.Fatalf("unexpected conflicts: %+v", conflicts)
		}
	})

	t.Run("existing wins with report", func(t *testing.T) {
		got, conflicts, err := MergeLabels(a, b, MergeKeepExisting)
		if err != nil {
			t.Fatal(err)
		}
		if v, _ := got.Get("shared"); v != "old" {
			t.Fatalf("shared value = %q, want old", v)
		}
		if len(conflicts) != 1 || conflicts[0].KeptValue != "old" {
			t.Fatalf("unexpected conflicts: %+v", conflicts)
		}
	})

	t.Run("reject", func(t *testing.T) {
		got, conflicts, err := MergeLabels(a, b, MergeReject)
		if err == nil {
			t.Fatal("expected conflict error")
		}
		if got != nil {
			t.Fatalf("strict merge returned labels with error: %v", got)
		}
		var conflictErr *LabelConflictError
		if !errors.As(err, &conflictErr) {
			t.Fatalf("expected *LabelConflictError, got %T", err)
		}
		if !errors.Is(err, ErrLabelConflict) || len(conflicts) != 1 {
			t.Fatalf("unexpected error/conflicts: %v / %v", err, conflicts)
		}
	})

	t.Run("equal values are not conflicts", func(t *testing.T) {
		equal := Labels{{Name: "shared", Value: "same"}}
		got, conflicts, err := MergeLabels(equal, equal, MergeReject)
		if err != nil || len(conflicts) != 0 {
			t.Fatalf("equal merge failed: got=%v conflicts=%v err=%v", got, conflicts, err)
		}
	})
}

func TestUID595LabelSetMergeCheckedAndConflictReport(t *testing.T) {
	a := LabelSet{"a": "1", "shared": "old"}
	b := LabelSet{"shared": "new", "b": "2"}

	merged, conflicts, err := a.MergeWithConflicts(b)
	if err != nil {
		t.Fatal(err)
	}
	if merged["shared"] != "new" || len(conflicts) != 1 {
		t.Fatalf("unexpected merge: %v conflicts=%v", merged, conflicts)
	}

	if _, err := a.MergeChecked(b); err == nil {
		t.Fatal("expected MergeChecked to reject differing value")
	} else if !errors.Is(err, ErrLabelConflict) {
		t.Fatalf("expected conflict sentinel, got %v", err)
	}

	// The historical compatible Merge API remains unchanged.
	if got := a.Merge(b); got["shared"] != "new" {
		t.Fatalf("existing Merge behavior changed: %v", got)
	}
}

func TestUID595NormalizeLabelSetJSONNullAndDuplicateKeys(t *testing.T) {
	input := []byte(`{"z":"last-z","a":"first","a":"last","empty":null,"ptr":null}`)
	labels, conflicts, err := NormalizeLabelSetJSON(input)
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := labels.Get("empty"); !ok || v != "" {
		t.Fatalf("null value = %q,%v; want empty string", v, ok)
	}
	if v, _ := labels.Get("a"); v != "last" {
		t.Fatalf("duplicate JSON key value = %q, want last", v)
	}
	if len(conflicts) == 0 {
		t.Fatal("expected duplicate JSON key conflict")
	}

	var ls LabelSet
	if err := json.Unmarshal([]byte(`{"name":"x","empty":null}`), &ls); err != nil {
		t.Fatal(err)
	}
	if ls["empty"] != "" {
		t.Fatalf("LabelSet JSON null = %q, want empty", ls["empty"])
	}
}

func TestUID595NormalizeLabelsAcceptsCommonRepresentations(t *testing.T) {
	want := Labels{{Name: "a", Value: "last"}, {Name: "b", Value: "2"}}
	last := "last"

	inputs := []any{
		LabelPairs{
			{Name: "a", Value: "first"},
			{Name: "a", Value: "last"},
			{Name: "b", Value: "2"},
		},
		map[string]string{"a": "last", "b": "2"},
		map[string]*string{"a": &last, "b": uid595PtrString("2")},
		map[string]any{"a": "last", "b": "2", "empty": nil},
		[]any{"a", "last", "b", "2"},
		[]*dto.LabelPair{
			{Name: uid595PtrString("a"), Value: uid595PtrString("last")},
			{Name: uid595PtrString("b"), Value: uid595PtrString("2")},
		},
	}

	for _, input := range inputs {
		t.Run(fmt.Sprintf("%T", input), func(t *testing.T) {
			got, _, err := NormalizeLabels(input)
			if err != nil {
				t.Fatalf("NormalizeLabels(%T) error: %v", input, err)
			}
			if _, ok := got.Get("empty"); ok {
				// The map[string]any case includes empty=nil; all other cases
				// do not. Remove it before the common comparison.
				if v, _ := got.Get("empty"); v != "" {
					t.Fatalf("nil value = %q, want empty", v)
				}
				got = slices.DeleteFunc(got, func(l Label) bool { return l.Name == "empty" })
			}
			if !uid595LabelsEqual(got, want) {
				t.Fatalf("got %v, want %v", got, want)
			}
		})
	}

}

func uid595PtrString(s string) *string { return &s }

func TestUID595LabelSetValidateNamesLabelInValueError(t *testing.T) {
	err := LabelSet{"region": "bad\xff"}.Validate()
	var invalid *InvalidLabelError
	if !errors.As(err, &invalid) || invalid.Name != "region" || invalid.Field != "value" {
		t.Fatalf("expected value error for region, got %v", err)
	}
}

func uid595LabelsEqual(a, b Labels) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func BenchmarkUID595NormalizeLabels50(b *testing.B) {
	pairs := make([]LabelPair, 50)
	for i := range pairs {
		pairs[i] = LabelPair{
			Name:  LabelName("label_" + string(rune('a'+i%26)) + "_" + strings.Repeat("x", i%5)),
			Value: LabelValue("value-" + string(rune('a'+i%26))),
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := NormalizeLabels(pairs); err != nil {
			b.Fatal(err)
		}
	}
}
