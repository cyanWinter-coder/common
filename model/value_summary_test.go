// Copyright The Prometheus Authors
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
	"math"
	"reflect"
	"strings"
	"testing"
)

func genSampleSummary() *SampleSummary {
	return &SampleSummary{
		Count: 6,
		Sum:   3897.3,
		Quantiles: Quantiles{
			{Quantile: 0.5, Value: 512.1},
			{Quantile: 0.9, Value: 2233.4},
			{Quantile: 0.99, Value: 4870.9},
		},
	}
}

func TestSampleSummaryPairJSON(t *testing.T) {
	input := []struct {
		plain string
		value SampleSummaryPair
	}{
		{
			plain: `[
				1234.567,
				{
					"count":"6",
					"sum":"3897.3",
					"quantiles":[
						["0.5","512.1"],
						["0.9","2233.4"],
						["0.99","4870.9"]
					]
				}
			]`,
			value: SampleSummaryPair{
				Summary:   genSampleSummary(),
				Timestamp: 1234567,
			},
		},
	}

	for _, test := range input {
		b, err := json.Marshal(test.value)
		if err != nil {
			t.Error(err)
			continue
		}

		trimmed := noWhitespace.ReplaceAllString(test.plain, "")
		if string(b) != trimmed {
			t.Errorf("encoding error: expected %q, got %q", trimmed, b)
			continue
		}

		var sp SampleSummaryPair
		err = json.Unmarshal(b, &sp)
		if err != nil {
			t.Error(err)
			continue
		}

		if !sp.Equal(&test.value) {
			t.Errorf("decoding error: expected %v, got %v", test.value, sp)
		}
	}
}

func TestInvalidSampleSummaryPairJSON(t *testing.T) {
	s1 := SampleSummaryPair{
		Timestamp: 1,
		Summary:   nil,
	}
	d, err := json.Marshal(s1)
	if err == nil {
		t.Errorf("expected error when trying to marshal invalid SampleSummaryPair %s", string(d))
	}

	var s2 SampleSummaryPair
	plain := "[0.001,null]"
	err = json.Unmarshal([]byte(plain), &s2)
	if err == nil {
		t.Errorf("expected error when trying to unmarshal invalid SampleSummaryPair %s", plain)
	}
}

func TestSampleSummaryJSON(t *testing.T) {
	input := []struct {
		plain string
		value Sample
	}{
		{
			plain: `{
				"metric":{
					"__name__":"test_metric"
				},
				"summary":[
					1234.567,
					{
						"count":"6",
						"sum":"3897.3",
						"quantiles":[
							["0.5","512.1"],
							["0.9","2233.4"],
							["0.99","4870.9"]
						]
					}
				]
			}`,
			value: Sample{
				Metric: Metric{
					MetricNameLabel: "test_metric",
				},
				Summary:   genSampleSummary(),
				Timestamp: 1234567,
			},
		},
	}

	for _, test := range input {
		b, err := json.Marshal(test.value)
		if err != nil {
			t.Error(err)
			continue
		}

		trimmed := noWhitespace.ReplaceAllString(test.plain, "")
		if string(b) != trimmed {
			t.Errorf("encoding error: expected %q, got %q", trimmed, b)
			continue
		}

		var sv Sample
		err = json.Unmarshal(b, &sv)
		if err != nil {
			t.Error(err)
			continue
		}

		if !reflect.DeepEqual(sv, test.value) {
			t.Errorf("decoding error: expected %v, got %v", test.value, sv)
		}
		if !sv.Equal(&test.value) {
			t.Errorf("equal error: expected %v, got %v", test.value, sv)
		}
	}
}

func TestSampleEqualAcrossTypes(t *testing.T) {
	summary := &Sample{Metric: Metric{MetricNameLabel: "m"}, Summary: genSampleSummary(), Timestamp: 1}
	value := &Sample{Metric: Metric{MetricNameLabel: "m"}, Value: 1, Timestamp: 1}
	histogram := &Sample{Metric: Metric{MetricNameLabel: "m"}, Histogram: genSampleHistogram(), Timestamp: 1}

	if summary.Equal(value) || value.Equal(summary) {
		t.Error("summary sample must not equal value sample")
	}
	if summary.Equal(histogram) || histogram.Equal(summary) {
		t.Error("summary sample must not equal histogram sample")
	}
	if !summary.Equal(summary) {
		t.Error("summary sample must equal itself")
	}
}

func TestSampleStreamSummariesJSON(t *testing.T) {
	input := []struct {
		plain string
		value SampleStream
	}{
		{
			plain: `{
				"metric":{"__name__":"test_metric"},
				"summaries":[
					[1234.567,{"count":"6","sum":"3897.3","quantiles":[["0.5","512.1"],["0.9","2233.4"],["0.99","4870.9"]]}]
				]
			}`,
			value: SampleStream{
				Metric: Metric{MetricNameLabel: "test_metric"},
				Summaries: []SampleSummaryPair{
					{Summary: genSampleSummary(), Timestamp: 1234567},
				},
			},
		},
		{
			plain: `{
				"metric":{"__name__":"test_metric"},
				"values":[[1234.567,"123.1"]],
				"summaries":[
					[1234.567,{"count":"6","sum":"3897.3","quantiles":[["0.5","512.1"],["0.9","2233.4"],["0.99","4870.9"]]}]
				]
			}`,
			value: SampleStream{
				Metric: Metric{MetricNameLabel: "test_metric"},
				Values: []SamplePair{
					{Value: 123.1, Timestamp: 1234567},
				},
				Summaries: []SampleSummaryPair{
					{Summary: genSampleSummary(), Timestamp: 1234567},
				},
			},
		},
	}

	for _, test := range input {
		b, err := json.Marshal(test.value)
		if err != nil {
			t.Error(err)
			continue
		}

		trimmed := noWhitespace.ReplaceAllString(test.plain, "")
		if string(b) != trimmed {
			t.Errorf("encoding error: expected %q, got %q", trimmed, b)
			continue
		}

		var ss SampleStream
		err = json.Unmarshal(b, &ss)
		if err != nil {
			t.Error(err)
			continue
		}

		if !reflect.DeepEqual(ss, test.value) {
			t.Errorf("decoding error: expected %v, got %v", test.value, ss)
		}
	}
}

func TestQuantilesValidate(t *testing.T) {
	tests := []struct {
		name      string
		quantiles Quantiles
		wantErr   string
	}{
		{name: "empty", quantiles: Quantiles{}},
		{name: "single", quantiles: Quantiles{{Quantile: 0.5, Value: 1}}},
		{
			name: "increasing",
			quantiles: Quantiles{
				{Quantile: 0, Value: 1},
				{Quantile: 0.5, Value: 2},
				{Quantile: 1, Value: 3},
			},
		},
		{
			name:      "out of range",
			quantiles: Quantiles{{Quantile: 1.5, Value: 1}},
			wantErr:   "[0, 1]",
		},
		{
			name:      "negative",
			quantiles: Quantiles{{Quantile: -0.1, Value: 1}},
			wantErr:   "[0, 1]",
		},
		{
			name:      "NaN",
			quantiles: Quantiles{{Quantile: FloatString(math.NaN()), Value: 1}},
			wantErr:   "[0, 1]",
		},
		{
			name: "out of order",
			quantiles: Quantiles{
				{Quantile: 0.9, Value: 1},
				{Quantile: 0.5, Value: 2},
			},
			wantErr: "quantile 1",
		},
		{
			name: "duplicate",
			quantiles: Quantiles{
				{Quantile: 0.5, Value: 1},
				{Quantile: 0.5, Value: 2},
			},
			wantErr: "quantile 1",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.quantiles.Validate()
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got none", test.wantErr)
			}
			if !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("expected error containing %q, got %q", test.wantErr, err.Error())
			}
		})
	}
}

func TestSampleSummaryInvalidQuantilesRejected(t *testing.T) {
	for _, in := range []string{
		`{"count":"1","sum":"1","quantiles":[["1.5","10"]]}`,
		`{"count":"1","sum":"1","quantiles":[["0.9","10"],["0.5","5"]]}`,
	} {
		var s SampleSummary
		if err := json.Unmarshal([]byte(in), &s); err == nil {
			t.Errorf("expected error for %s, got none", in)
		}
	}
}

func TestSampleSummaryUnknownFieldsPreserved(t *testing.T) {
	in := `{"count":"6","sum":"3897.3","quantiles":[["0.5","512.1"]],"created":"2026-01-01"}`
	var s SampleSummary
	if err := json.Unmarshal([]byte(in), &s); err != nil {
		t.Fatal(err)
	}
	b1, err := json.Marshal(&s)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b1), `"created":"2026-01-01"`) {
		t.Errorf("unknown field not preserved: %s", b1)
	}

	var s2 SampleSummary
	if err := json.Unmarshal(b1, &s2); err != nil {
		t.Fatal(err)
	}
	b2, err := json.Marshal(&s2)
	if err != nil {
		t.Fatal(err)
	}
	if string(b1) != string(b2) {
		t.Errorf("round-trip not idempotent:\nfirst:  %s\nsecond: %s", b1, b2)
	}
}

func TestSampleSummaryEmptyAndSpecialValues(t *testing.T) {
	inputs := []string{
		`{"count":"0","sum":"0","quantiles":[]}`,
		`{"count":"0","sum":"0","quantiles":null}`,
		`{"count":"0","sum":"0"}`,
		`{"count":"1","sum":"+Inf","quantiles":[["0.5","NaN"]]}`,
	}
	for _, in := range inputs {
		var s SampleSummary
		if err := json.Unmarshal([]byte(in), &s); err != nil {
			t.Errorf("unmarshal %s: %v", in, err)
			continue
		}
		b1, err := json.Marshal(&s)
		if err != nil {
			t.Errorf("marshal %s: %v", in, err)
			continue
		}
		var s2 SampleSummary
		if err := json.Unmarshal(b1, &s2); err != nil {
			t.Errorf("re-unmarshal %s: %v", b1, err)
			continue
		}
		b2, err := json.Marshal(&s2)
		if err != nil {
			t.Errorf("re-marshal %s: %v", b1, err)
			continue
		}
		if string(b1) != string(b2) {
			t.Errorf("round-trip of %s not idempotent: %s != %s", in, b1, b2)
		}
	}
}
