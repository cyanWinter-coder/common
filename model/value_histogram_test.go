// Copyright 2013 The Prometheus Authors
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
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	noWhitespace = regexp.MustCompile(`\s`)

	sampleHistogramPairMatrixPlain = `[
		{
			"metric":{
				"__name__":"test_metric"
			},
			"histograms":[
				[
					1234.567,
					{
					"count":"6",
					"sum":"3897",
					"buckets":[
						[
							1,
							"-4870.992343051145",
							"-4466.7196729968955",
							"1"
						],
						[
							1,
							"-861.0779292198035",
							"-789.6119426088657",
							"1"
						],
						[
							1,
							"-558.3399591246119",
							"-512",
							"1"
						],
						[
							0,
							"2048",
							"2233.3598364984477",
							"1"
						],
						[
							0,
							"2896.3093757400984",
							"3158.4477704354626",
							"1"
						],
						[
							0,
							"4466.7196729968955",
							"4870.992343051145",
							"1"
						]
					]
					}
				],
				[
					12345.678,
					{
					"count":"6",
					"sum":"3897",
					"buckets":[
						[
							1,
							"-4870.992343051145",
							"-4466.7196729968955",
							"1"
						],
						[
							1,
							"-861.0779292198035",
							"-789.6119426088657",
							"1"
						],
						[
							1,
							"-558.3399591246119",
							"-512",
							"1"
						],
						[
							0,
							"2048",
							"2233.3598364984477",
							"1"
						],
						[
							0,
							"2896.3093757400984",
							"3158.4477704354626",
							"1"
						],
						[
							0,
							"4466.7196729968955",
							"4870.992343051145",
							"1"
						]
					]
					}
				]
			]
		},
		{
			"metric":{
				"foo":"bar"
			},
			"histograms":[
				[
					2234.567,
					{
					"count":"6",
					"sum":"3897",
					"buckets":[
						[
							1,
							"-4870.992343051145",
							"-4466.7196729968955",
							"1"
						],
						[
							1,
							"-861.0779292198035",
							"-789.6119426088657",
							"1"
						],
						[
							1,
							"-558.3399591246119",
							"-512",
							"1"
						],
						[
							0,
							"2048",
							"2233.3598364984477",
							"1"
						],
						[
							0,
							"2896.3093757400984",
							"3158.4477704354626",
							"1"
						],
						[
							0,
							"4466.7196729968955",
							"4870.992343051145",
							"1"
						]
					]
					}
				],
				[
					22345.678,
					{
					"count":"6",
					"sum":"3897",
					"buckets":[
						[
							1,
							"-4870.992343051145",
							"-4466.7196729968955",
							"1"
						],
						[
							1,
							"-861.0779292198035",
							"-789.6119426088657",
							"1"
						],
						[
							1,
							"-558.3399591246119",
							"-512",
							"1"
						],
						[
							0,
							"2048",
							"2233.3598364984477",
							"1"
						],
						[
							0,
							"2896.3093757400984",
							"3158.4477704354626",
							"1"
						],
						[
							0,
							"4466.7196729968955",
							"4870.992343051145",
							"1"
						]
					]
					}
				]
			]
		}
	]`
	sampleHistogramPairMatrixValue = Matrix{
		&SampleStream{
			Metric: Metric{
				MetricNameLabel: "test_metric",
			},
			Histograms: []SampleHistogramPair{
				{
					Histogram: genSampleHistogram(),
					Timestamp: 1234567,
				},
				{
					Histogram: genSampleHistogram(),
					Timestamp: 12345678,
				},
			},
		},
		&SampleStream{
			Metric: Metric{
				"foo": "bar",
			},
			Histograms: []SampleHistogramPair{
				{
					Histogram: genSampleHistogram(),
					Timestamp: 2234567,
				},
				{
					Histogram: genSampleHistogram(),
					Timestamp: 22345678,
				},
			},
		},
	}
)

func genSampleHistogram() *SampleHistogram {
	return &SampleHistogram{
		Count: 6,
		Sum:   3897,
		Buckets: HistogramBuckets{
			{
				Boundaries: 1,
				Lower:      -4870.992343051145,
				Upper:      -4466.7196729968955,
				Count:      1,
			},
			{
				Boundaries: 1,
				Lower:      -861.0779292198035,
				Upper:      -789.6119426088657,
				Count:      1,
			},
			{
				Boundaries: 1,
				Lower:      -558.3399591246119,
				Upper:      -512,
				Count:      1,
			},
			{
				Boundaries: 0,
				Lower:      2048,
				Upper:      2233.3598364984477,
				Count:      1,
			},
			{
				Boundaries: 0,
				Lower:      2896.3093757400984,
				Upper:      3158.4477704354626,
				Count:      1,
			},
			{
				Boundaries: 0,
				Lower:      4466.7196729968955,
				Upper:      4870.992343051145,
				Count:      1,
			},
		},
	}
}

func TestSampleHistogramPairJSON(t *testing.T) {
	input := []struct {
		plain string
		value SampleHistogramPair
	}{
		{
			plain: `[
				1234.567,
				{
					"count":"6",
					"sum":"3897",
					"buckets":[
						[
							1,
							"-4870.992343051145",
							"-4466.7196729968955",
							"1"
						],
						[
							1,
							"-861.0779292198035",
							"-789.6119426088657",
							"1"
						],
						[
							1,
							"-558.3399591246119",
							"-512",
							"1"
						],
						[
							0,
							"2048",
							"2233.3598364984477",
							"1"
						],
						[
							0,
							"2896.3093757400984",
							"3158.4477704354626",
							"1"
						],
						[
							0,
							"4466.7196729968955",
							"4870.992343051145",
							"1"
						]
					]
				}
			]`,
			value: SampleHistogramPair{
				Histogram: genSampleHistogram(),
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

		var sp SampleHistogramPair
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

func TestInvalidSampleHistogramPairJSON(t *testing.T) {
	s1 := SampleHistogramPair{
		Timestamp: 1,
		Histogram: nil,
	}
	d, err := json.Marshal(s1)
	if err == nil {
		t.Errorf("expected error when trying to marshal invalid SampleHistogramPair %s", string(d))
	}

	var s2 SampleHistogramPair
	plain := "[0.001,null]"
	err = json.Unmarshal([]byte(plain), &s2)
	if err == nil {
		t.Errorf("expected error when trying to unmarshal invalid SampleHistogramPair %s", plain)
	}
}

func TestSampleHistogramJSON(t *testing.T) {
	input := []struct {
		plain string
		value Sample
	}{
		{
			plain: `{
				"metric":{
					"__name__":"test_metric"
				},
				"histogram":[
					1234.567,
					{
						"count":"6",
						"sum":"3897",
						"buckets":[
							[
								1,
								"-4870.992343051145",
								"-4466.7196729968955",
								"1"
							],
							[
								1,
								"-861.0779292198035",
								"-789.6119426088657",
								"1"
							],
							[
								1,
								"-558.3399591246119",
								"-512",
								"1"
							],
							[
								0,
								"2048",
								"2233.3598364984477",
								"1"
							],
							[
								0,
								"2896.3093757400984",
								"3158.4477704354626",
								"1"
							],
							[
								0,
								"4466.7196729968955",
								"4870.992343051145",
								"1"
							]
						]
					}
				]
			}`,
			value: Sample{
				Metric: Metric{
					MetricNameLabel: "test_metric",
				},
				Histogram: genSampleHistogram(),
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
	}
}

func TestVectorHistogramJSON(t *testing.T) {
	input := []struct {
		plain string
		value Vector
	}{
		{
			plain: `[
				{
					"metric":{
						"__name__":"test_metric"
					},
					"histogram":[
						1234.567,
						{
							"count":"6",
							"sum":"3897",
							"buckets":[
							[
								1,
								"-4870.992343051145",
								"-4466.7196729968955",
								"1"
							],
							[
								1,
								"-861.0779292198035",
								"-789.6119426088657",
								"1"
							],
							[
								1,
								"-558.3399591246119",
								"-512",
								"1"
							],
							[
								0,
								"2048",
								"2233.3598364984477",
								"1"
							],
							[
								0,
								"2896.3093757400984",
								"3158.4477704354626",
								"1"
							],
							[
								0,
								"4466.7196729968955",
								"4870.992343051145",
								"1"
							]
							]
						}
					]
				}
			]`,
			value: Vector{&Sample{
				Metric: Metric{
					MetricNameLabel: "test_metric",
				},
				Histogram: genSampleHistogram(),
				Timestamp: 1234567,
			}},
		},
		{
			plain: `[
				{
					"metric":{
						"__name__":"test_metric"
					},
					"histogram":[
						1234.567,
						{
							"count":"6",
							"sum":"3897",
							"buckets":[
							[
								1,
								"-4870.992343051145",
								"-4466.7196729968955",
								"1"
							],
							[
								1,
								"-861.0779292198035",
								"-789.6119426088657",
								"1"
							],
							[
								1,
								"-558.3399591246119",
								"-512",
								"1"
							],
							[
								0,
								"2048",
								"2233.3598364984477",
								"1"
							],
							[
								0,
								"2896.3093757400984",
								"3158.4477704354626",
								"1"
							],
							[
								0,
								"4466.7196729968955",
								"4870.992343051145",
								"1"
							]
							]
						}
					]
				},
				{
					"metric":{
						"foo":"bar"
					},
					"histogram":[
						1.234,
						{
							"count":"6",
							"sum":"3897",
							"buckets":[
							[
								1,
								"-4870.992343051145",
								"-4466.7196729968955",
								"1"
							],
							[
								1,
								"-861.0779292198035",
								"-789.6119426088657",
								"1"
							],
							[
								1,
								"-558.3399591246119",
								"-512",
								"1"
							],
							[
								0,
								"2048",
								"2233.3598364984477",
								"1"
							],
							[
								0,
								"2896.3093757400984",
								"3158.4477704354626",
								"1"
							],
							[
								0,
								"4466.7196729968955",
								"4870.992343051145",
								"1"
							]
							]
						}
					]
				}
			]`,
			value: Vector{
				&Sample{
					Metric: Metric{
						MetricNameLabel: "test_metric",
					},
					Histogram: genSampleHistogram(),
					Timestamp: 1234567,
				},
				&Sample{
					Metric: Metric{
						"foo": "bar",
					},
					Histogram: genSampleHistogram(),
					Timestamp: 1234,
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

		var vec Vector
		err = json.Unmarshal(b, &vec)
		if err != nil {
			t.Error(err)
			continue
		}

		if !reflect.DeepEqual(vec, test.value) {
			t.Errorf("decoding error: expected %v, got %v", test.value, vec)
		}
	}
}

func TestMatrixHistogramJSON(t *testing.T) {
	input := []struct {
		plain string
		value Matrix
	}{
		{
			plain: `[]`,
			value: Matrix{},
		},
		{
			plain: sampleHistogramPairMatrixPlain,
			value: sampleHistogramPairMatrixValue,
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

		var mat Matrix
		err = json.Unmarshal(b, &mat)
		if err != nil {
			t.Error(err)
			continue
		}

		if !reflect.DeepEqual(mat, test.value) {
			t.Errorf("decoding error: expected %v, got %v", test.value, mat)
		}
	}
}

func BenchmarkJSONMarshallingSampleHistogramPairMatrix(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := json.Marshal(sampleHistogramPairMatrixValue)
		require.NoErrorf(b, err, "error marshalling")
	}
}

func TestFloatStringSpecialValues(t *testing.T) {
	for _, f := range []float64{
		math.NaN(), math.Inf(1), math.Inf(-1),
		1e-320, 5e-324, // denormals must not expand to hundreds of digits or collapse to 0.
		1e300, -1e300,
		0, 0.1, -512, 2048, 2233.3598364984477,
	} {
		fs := FloatString(f)
		b, err := json.Marshal(fs)
		if err != nil {
			t.Fatalf("marshal %v: %v", f, err)
		}
		var back FloatString
		if err := json.Unmarshal(b, &back); err != nil {
			t.Fatalf("unmarshal %s: %v", b, err)
		}
		switch {
		case math.IsNaN(f):
			if !math.IsNaN(float64(back)) {
				t.Errorf("NaN did not round-trip: got %v (%s)", float64(back), b)
			}
		case math.IsInf(f, 0):
			if !math.IsInf(float64(back), int(math.Copysign(1, f))) {
				t.Errorf("Inf did not round-trip: got %v (%s)", float64(back), b)
			}
		default:
			if float64(back) != f {
				t.Errorf("%v did not round-trip: got %v (%s)", f, float64(back), b)
			}
		}
		if s := fs.String(); len(s) > 25 {
			t.Errorf("String() of %v is %d chars (%q), want compact notation", f, len(s), s)
		}
	}

	// NaN and Inf must come back as floats, not as strings or zeros.
	var h SampleHistogram
	if err := json.Unmarshal([]byte(`{"count":"3","sum":"NaN","buckets":[[3,"0","+Inf","3"]]}`), &h); err != nil {
		t.Fatal(err)
	}
	if !math.IsNaN(float64(h.Sum)) {
		t.Errorf("sum: expected NaN, got %v", float64(h.Sum))
	}
	if !math.IsInf(float64(h.Buckets[0].Upper), 1) {
		t.Errorf("upper bound: expected +Inf, got %v", float64(h.Buckets[0].Upper))
	}
}

func TestFloatStringUnquotedJSON(t *testing.T) {
	var v FloatString
	if err := json.Unmarshal([]byte(`1.5`), &v); err != nil {
		t.Fatalf("bare number rejected: %v", err)
	}
	if v != 1.5 {
		t.Errorf("expected 1.5, got %v", v)
	}
	if err := json.Unmarshal([]byte(`"2.5"`), &v); err != nil {
		t.Fatalf("quoted number rejected: %v", err)
	}
	if v != 2.5 {
		t.Errorf("expected 2.5, got %v", v)
	}
	if err := json.Unmarshal([]byte(`"not-a-number"`), &v); err == nil {
		t.Error("expected error for invalid value")
	}
}

func TestHistogramBucketsValidate(t *testing.T) {
	tests := []struct {
		name    string
		buckets HistogramBuckets
		wantErr string
	}{
		{name: "empty", buckets: HistogramBuckets{}},
		{name: "nil", buckets: nil},
		{
			name: "single bucket",
			buckets: HistogramBuckets{
				{Boundaries: 3, Lower: 0, Upper: 10, Count: 1},
			},
		},
		{
			name: "single +Inf bucket",
			buckets: HistogramBuckets{
				{Boundaries: 3, Lower: 0, Upper: FloatString(math.Inf(1)), Count: 1},
			},
		},
		{
			name: "increasing",
			buckets: HistogramBuckets{
				{Boundaries: 1, Lower: -10, Upper: -5, Count: 1},
				{Boundaries: 3, Lower: -5, Upper: 0, Count: 1},
				{Boundaries: 3, Lower: 0, Upper: 5, Count: 1},
			},
		},
		{
			name: "reversed order",
			buckets: HistogramBuckets{
				{Boundaries: 1, Lower: 0, Upper: 10, Count: 1},
				{Boundaries: 1, Lower: 0, Upper: 5, Count: 1},
			},
			wantErr: "bucket 1",
		},
		{
			name: "overlapping equal upper bounds",
			buckets: HistogramBuckets{
				{Boundaries: 1, Lower: 0, Upper: 10, Count: 1},
				{Boundaries: 1, Lower: 2, Upper: 10, Count: 1},
			},
			wantErr: "bucket 1",
		},
		{
			name: "lower greater than upper",
			buckets: HistogramBuckets{
				{Boundaries: 1, Lower: 10, Upper: 5, Count: 1},
			},
			wantErr: "bucket 0",
		},
		{
			name: "NaN bound",
			buckets: HistogramBuckets{
				{Boundaries: 1, Lower: 0, Upper: FloatString(math.NaN()), Count: 1},
			},
			wantErr: "NaN",
		},
		{
			name:    "nil bucket",
			buckets: HistogramBuckets{nil},
			wantErr: "nil",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.buckets.Validate()
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

func TestSampleHistogramUnsortedBucketsRejected(t *testing.T) {
	for _, in := range []string{
		`{"count":"2","sum":"1","buckets":[[1,"0","10","1"],[1,"0","5","1"]]}`,
		`{"count":"2","sum":"1","buckets":[[1,"0","10","1"],[1,"5","10","1"]]}`,
		`{"count":"1","sum":"1","buckets":[[1,"10","5","1"]]}`,
	} {
		var h SampleHistogram
		err := json.Unmarshal([]byte(in), &h)
		if err == nil {
			t.Errorf("expected error for %s, got none", in)
		}
	}
}

func TestSampleHistogramUnknownFieldsPreserved(t *testing.T) {
	in := `{"count":"6","sum":"3897","buckets":[[1,"0","+Inf","6"]],"zeroCount":"0","schema":3}`
	var h SampleHistogram
	if err := json.Unmarshal([]byte(in), &h); err != nil {
		t.Fatal(err)
	}
	b1, err := json.Marshal(&h)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"zeroCount":"0"`, `"schema":3`, `"count":"6"`, `"sum":"3897"`} {
		if !strings.Contains(string(b1), want) {
			t.Errorf("marshaled histogram %s missing %s", b1, want)
		}
	}

	// A second round-trip must be byte-identical (idempotent).
	var h2 SampleHistogram
	if err := json.Unmarshal(b1, &h2); err != nil {
		t.Fatal(err)
	}
	b2, err := json.Marshal(&h2)
	if err != nil {
		t.Fatal(err)
	}
	if string(b1) != string(b2) {
		t.Errorf("round-trip not idempotent:\nfirst:  %s\nsecond: %s", b1, b2)
	}
}

func TestSampleHistogramEmptyAndSingleBucket(t *testing.T) {
	inputs := []string{
		`{"count":"0","sum":"0","buckets":[]}`,
		`{"count":"0","sum":"0","buckets":null}`,
		`{"count":"0","sum":"0"}`,
		`{"count":"1","sum":"0.5","buckets":[[3,"0","+Inf","1"]]}`,
	}
	for _, in := range inputs {
		var h SampleHistogram
		if err := json.Unmarshal([]byte(in), &h); err != nil {
			t.Errorf("unmarshal %s: %v", in, err)
			continue
		}
		b1, err := json.Marshal(&h)
		if err != nil {
			t.Errorf("marshal %s: %v", in, err)
			continue
		}
		var h2 SampleHistogram
		if err := json.Unmarshal(b1, &h2); err != nil {
			t.Errorf("re-unmarshal %s: %v", b1, err)
			continue
		}
		b2, err := json.Marshal(&h2)
		if err != nil {
			t.Errorf("re-marshal %s: %v", b1, err)
			continue
		}
		if string(b1) != string(b2) {
			t.Errorf("round-trip of %s not idempotent: %s != %s", in, b1, b2)
		}
	}
}

func TestSampleHistogramStringTinyValues(t *testing.T) {
	h := SampleHistogram{Count: FloatString(1e-9), Sum: FloatString(2.5e-310)}
	s := h.String()
	if strings.Contains(s, "0.000000") {
		t.Errorf("tiny values rendered as zero: %s", s)
	}
	if !strings.Contains(s, "1e-09") || !strings.Contains(s, "2.5e-310") {
		t.Errorf("tiny values not rendered in exponent notation: %s", s)
	}
}
