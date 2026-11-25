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
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

type FloatString float64

// String returns the shortest string that parses back to exactly v, using
// exponent notation for very large or very small magnitudes so that denormal
// or extreme values stay compact instead of expanding to hundreds of digits.
// NaN and infinities are rendered as "NaN", "+Inf" and "-Inf", matching the
// Prometheus text format.
func (v FloatString) String() string {
	return strconv.FormatFloat(float64(v), 'g', -1, 64)
}

func (v FloatString) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.String())
}

// UnmarshalJSON accepts the quoted string form produced by MarshalJSON
// (including "NaN", "+Inf" and "-Inf") as well as a bare JSON number, so
// that payloads from sources that do not quote their floats still parse.
func (v *FloatString) UnmarshalJSON(b []byte) error {
	if len(b) >= 2 && b[0] == '"' && b[len(b)-1] == '"' {
		b = b[1 : len(b)-1]
	}
	f, err := strconv.ParseFloat(string(b), 64)
	if err != nil {
		return fmt.Errorf("error parsing float value %s: %w", b, err)
	}
	*v = FloatString(f)
	return nil
}

type HistogramBucket struct {
	Boundaries int32
	Lower      FloatString
	Upper      FloatString
	Count      FloatString
}

func (s HistogramBucket) MarshalJSON() ([]byte, error) {
	b, err := json.Marshal(s.Boundaries)
	if err != nil {
		return nil, err
	}
	l, err := json.Marshal(s.Lower)
	if err != nil {
		return nil, err
	}
	u, err := json.Marshal(s.Upper)
	if err != nil {
		return nil, err
	}
	c, err := json.Marshal(s.Count)
	if err != nil {
		return nil, err
	}
	return fmt.Appendf(nil, "[%s,%s,%s,%s]", b, l, u, c), nil
}

func (s *HistogramBucket) UnmarshalJSON(buf []byte) error {
	tmp := []any{&s.Boundaries, &s.Lower, &s.Upper, &s.Count}
	wantLen := len(tmp)
	if err := json.Unmarshal(buf, &tmp); err != nil {
		return err
	}
	if gotLen := len(tmp); gotLen != wantLen {
		return fmt.Errorf("wrong number of fields: %d != %d", gotLen, wantLen)
	}
	return nil
}

func (s *HistogramBucket) Equal(o *HistogramBucket) bool {
	return s == o || (s.Boundaries == o.Boundaries && s.Lower == o.Lower && s.Upper == o.Upper && s.Count == o.Count)
}

func (s HistogramBucket) String() string {
	var sb strings.Builder
	lowerInclusive := s.Boundaries == 1 || s.Boundaries == 3
	upperInclusive := s.Boundaries == 0 || s.Boundaries == 3
	if lowerInclusive {
		sb.WriteRune('[')
	} else {
		sb.WriteRune('(')
	}
	fmt.Fprintf(&sb, "%g,%g", s.Lower, s.Upper)
	if upperInclusive {
		sb.WriteRune(']')
	} else {
		sb.WriteRune(')')
	}
	fmt.Fprintf(&sb, ":%v", s.Count)
	return sb.String()
}

type HistogramBuckets []*HistogramBucket

func (s HistogramBuckets) Equal(o HistogramBuckets) bool {
	if len(s) != len(o) {
		return false
	}

	for i, bucket := range s {
		if !bucket.Equal(o[i]) {
			return false
		}
	}
	return true
}

// Validate checks that the buckets are well-formed: no nil buckets, no NaN
// bounds, lower bound not greater than upper bound, and upper bounds strictly
// increasing. Overlapping, equal or out-of-order upper bounds are rejected
// with an error naming the offending bucket. Empty and single-bucket slices
// are always valid.
func (s HistogramBuckets) Validate() error {
	for i, b := range s {
		if b == nil {
			return fmt.Errorf("histogram bucket %d is nil", i)
		}
		lower, upper := float64(b.Lower), float64(b.Upper)
		if math.IsNaN(lower) || math.IsNaN(upper) {
			return fmt.Errorf("histogram bucket %d: bounds must not be NaN, got [%v, %v]", i, b.Lower, b.Upper)
		}
		if lower > upper {
			return fmt.Errorf("histogram bucket %d: lower bound %v is greater than upper bound %v", i, b.Lower, b.Upper)
		}
		if i > 0 && upper <= float64(s[i-1].Upper) {
			return fmt.Errorf("histogram bucket %d: upper bound %v is not greater than upper bound %v of bucket %d: buckets must be sorted by strictly increasing upper bound", i, b.Upper, s[i-1].Upper, i-1)
		}
	}
	return nil
}

type SampleHistogram struct {
	Count   FloatString      `json:"count"`
	Sum     FloatString      `json:"sum"`
	Buckets HistogramBuckets `json:"buckets"`
	// ExtraFields holds members of the JSON object that are not known to
	// this package, keyed by member name. They are emitted again by
	// MarshalJSON so that a JSON round-trip preserves them. It is nil when
	// no unknown members were decoded.
	ExtraFields map[string]json.RawMessage `json:"-"`
}

// MarshalJSON implements json.Marshaler. Known members are emitted in a
// fixed order (count, sum, buckets), followed by any ExtraFields ordered by
// key, so the output is deterministic and round-trips idempotently.
func (s SampleHistogram) MarshalJSON() ([]byte, error) {
	c, err := json.Marshal(s.Count)
	if err != nil {
		return nil, err
	}
	su, err := json.Marshal(s.Sum)
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(s.Buckets)
	if err != nil {
		return nil, err
	}
	out := fmt.Appendf(nil, `{"count":%s,"sum":%s,"buckets":%s`, c, su, b)
	out = appendExtraFields(out, s.ExtraFields)
	return append(out, '}'), nil
}

// UnmarshalJSON implements json.Unmarshaler. Members not known to this
// package are retained in ExtraFields. The buckets are validated and an
// error is returned if they overlap or are out of order.
func (s *SampleHistogram) UnmarshalJSON(b []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return fmt.Errorf("error decoding sample histogram: %w", err)
	}
	for k, v := range raw {
		switch k {
		case "count":
			if err := s.Count.UnmarshalJSON(v); err != nil {
				return fmt.Errorf("error decoding histogram count: %w", err)
			}
		case "sum":
			if err := s.Sum.UnmarshalJSON(v); err != nil {
				return fmt.Errorf("error decoding histogram sum: %w", err)
			}
		case "buckets":
			if err := json.Unmarshal(v, &s.Buckets); err != nil {
				return fmt.Errorf("error decoding histogram buckets: %w", err)
			}
		default:
			if s.ExtraFields == nil {
				s.ExtraFields = map[string]json.RawMessage{}
			}
			s.ExtraFields[k] = v
		}
	}
	return s.Buckets.Validate()
}

// appendExtraFields appends the given extra JSON object members to out,
// which must not yet have its closing brace, ordered by key for
// deterministic output.
func appendExtraFields(out []byte, extra map[string]json.RawMessage) []byte {
	if len(extra) == 0 {
		return out
	}
	keys := make([]string, 0, len(extra))
	for k := range extra {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		kJSON, err := json.Marshal(k)
		if err != nil {
			continue
		}
		out = append(out, ',')
		out = append(out, kJSON...)
		out = append(out, ':')
		out = append(out, extra[k]...)
	}
	return out
}

func (s SampleHistogram) String() string {
	return fmt.Sprintf("Count: %v, Sum: %v, Buckets: %v", s.Count, s.Sum, s.Buckets)
}

func (s *SampleHistogram) Equal(o *SampleHistogram) bool {
	return s == o || (s.Count == o.Count && s.Sum == o.Sum && s.Buckets.Equal(o.Buckets))
}

type SampleHistogramPair struct {
	Timestamp Time
	// Histogram should never be nil, it's only stored as pointer for efficiency.
	Histogram *SampleHistogram
}

func (s SampleHistogramPair) MarshalJSON() ([]byte, error) {
	if s.Histogram == nil {
		return nil, errors.New("histogram is nil")
	}
	t, err := json.Marshal(s.Timestamp)
	if err != nil {
		return nil, err
	}
	v, err := json.Marshal(s.Histogram)
	if err != nil {
		return nil, err
	}
	return fmt.Appendf(nil, "[%s,%s]", t, v), nil
}

func (s *SampleHistogramPair) UnmarshalJSON(buf []byte) error {
	tmp := []any{&s.Timestamp, &s.Histogram}
	wantLen := len(tmp)
	if err := json.Unmarshal(buf, &tmp); err != nil {
		return err
	}
	if gotLen := len(tmp); gotLen != wantLen {
		return fmt.Errorf("wrong number of fields: %d != %d", gotLen, wantLen)
	}
	if s.Histogram == nil {
		return errors.New("histogram is null")
	}
	return nil
}

func (s SampleHistogramPair) String() string {
	return fmt.Sprintf("%s @[%s]", s.Histogram, s.Timestamp)
}

func (s *SampleHistogramPair) Equal(o *SampleHistogramPair) bool {
	return s == o || (s.Histogram.Equal(o.Histogram) && s.Timestamp.Equal(o.Timestamp))
}
