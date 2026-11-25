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
	"errors"
	"fmt"
	"math"
)

// Quantile is a quantile/value pair within a summary sample, e.g. the 0.9
// quantile and the observed value at that quantile.
type Quantile struct {
	Quantile FloatString
	Value    FloatString
}

func (q Quantile) MarshalJSON() ([]byte, error) {
	quantile, err := json.Marshal(q.Quantile)
	if err != nil {
		return nil, err
	}
	v, err := json.Marshal(q.Value)
	if err != nil {
		return nil, err
	}
	return fmt.Appendf(nil, "[%s,%s]", quantile, v), nil
}

func (q *Quantile) UnmarshalJSON(buf []byte) error {
	tmp := []any{&q.Quantile, &q.Value}
	wantLen := len(tmp)
	if err := json.Unmarshal(buf, &tmp); err != nil {
		return err
	}
	if gotLen := len(tmp); gotLen != wantLen {
		return fmt.Errorf("wrong number of fields: %d != %d", gotLen, wantLen)
	}
	return nil
}

func (q *Quantile) Equal(o *Quantile) bool {
	return q == o || (q.Quantile == o.Quantile && q.Value == o.Value)
}

func (q Quantile) String() string {
	return fmt.Sprintf("%v: %v", q.Quantile, q.Value)
}

type Quantiles []*Quantile

func (s Quantiles) Equal(o Quantiles) bool {
	if len(s) != len(o) {
		return false
	}

	for i, quantile := range s {
		if !quantile.Equal(o[i]) {
			return false
		}
	}
	return true
}

// Validate checks that the quantiles are well-formed: no nil entries, every
// quantile within [0, 1] and not NaN, and quantiles strictly increasing.
// Empty and single-entry slices are always valid.
func (s Quantiles) Validate() error {
	for i, q := range s {
		if q == nil {
			return fmt.Errorf("summary quantile %d is nil", i)
		}
		quantile := float64(q.Quantile)
		if math.IsNaN(quantile) || quantile < 0 || quantile > 1 {
			return fmt.Errorf("summary quantile %d: quantile %v is not within [0, 1]", i, q.Quantile)
		}
		if i > 0 && quantile <= float64(s[i-1].Quantile) {
			return fmt.Errorf("summary quantile %d: quantile %v is not greater than quantile %v of entry %d: quantiles must be sorted by strictly increasing quantile", i, q.Quantile, s[i-1].Quantile, i-1)
		}
	}
	return nil
}

// SampleSummary is a summary sample: a cumulative count and sum of observed
// values together with the values at a set of quantiles.
type SampleSummary struct {
	Count     FloatString `json:"count"`
	Sum       FloatString `json:"sum"`
	Quantiles Quantiles   `json:"quantiles"`
	// ExtraFields holds members of the JSON object that are not known to
	// this package, keyed by member name. They are emitted again by
	// MarshalJSON so that a JSON round-trip preserves them. It is nil when
	// no unknown members were decoded.
	ExtraFields map[string]json.RawMessage `json:"-"`
}

// MarshalJSON implements json.Marshaler. Known members are emitted in a
// fixed order (count, sum, quantiles), followed by any ExtraFields ordered
// by key, so the output is deterministic and round-trips idempotently.
func (s SampleSummary) MarshalJSON() ([]byte, error) {
	c, err := json.Marshal(s.Count)
	if err != nil {
		return nil, err
	}
	su, err := json.Marshal(s.Sum)
	if err != nil {
		return nil, err
	}
	q, err := json.Marshal(s.Quantiles)
	if err != nil {
		return nil, err
	}
	out := fmt.Appendf(nil, `{"count":%s,"sum":%s,"quantiles":%s`, c, su, q)
	out = appendExtraFields(out, s.ExtraFields)
	return append(out, '}'), nil
}

// UnmarshalJSON implements json.Unmarshaler. Members not known to this
// package are retained in ExtraFields. The quantiles are validated and an
// error is returned if they are out of range or out of order.
func (s *SampleSummary) UnmarshalJSON(b []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return fmt.Errorf("error decoding sample summary: %w", err)
	}
	for k, v := range raw {
		switch k {
		case "count":
			if err := s.Count.UnmarshalJSON(v); err != nil {
				return fmt.Errorf("error decoding summary count: %w", err)
			}
		case "sum":
			if err := s.Sum.UnmarshalJSON(v); err != nil {
				return fmt.Errorf("error decoding summary sum: %w", err)
			}
		case "quantiles":
			if err := json.Unmarshal(v, &s.Quantiles); err != nil {
				return fmt.Errorf("error decoding summary quantiles: %w", err)
			}
		default:
			if s.ExtraFields == nil {
				s.ExtraFields = map[string]json.RawMessage{}
			}
			s.ExtraFields[k] = v
		}
	}
	return s.Quantiles.Validate()
}

func (s SampleSummary) String() string {
	return fmt.Sprintf("Count: %v, Sum: %v, Quantiles: %v", s.Count, s.Sum, s.Quantiles)
}

func (s *SampleSummary) Equal(o *SampleSummary) bool {
	return s == o || (s.Count == o.Count && s.Sum == o.Sum && s.Quantiles.Equal(o.Quantiles))
}

// SampleSummaryPair pairs a SampleSummary with a Timestamp.
type SampleSummaryPair struct {
	Timestamp Time
	// Summary should never be nil, it's only stored as pointer for efficiency.
	Summary *SampleSummary
}

func (s SampleSummaryPair) MarshalJSON() ([]byte, error) {
	if s.Summary == nil {
		return nil, errors.New("summary is nil")
	}
	t, err := json.Marshal(s.Timestamp)
	if err != nil {
		return nil, err
	}
	v, err := json.Marshal(s.Summary)
	if err != nil {
		return nil, err
	}
	return fmt.Appendf(nil, "[%s,%s]", t, v), nil
}

func (s *SampleSummaryPair) UnmarshalJSON(buf []byte) error {
	tmp := []any{&s.Timestamp, &s.Summary}
	wantLen := len(tmp)
	if err := json.Unmarshal(buf, &tmp); err != nil {
		return err
	}
	if gotLen := len(tmp); gotLen != wantLen {
		return fmt.Errorf("wrong number of fields: %d != %d", gotLen, wantLen)
	}
	if s.Summary == nil {
		return errors.New("summary is null")
	}
	return nil
}

func (s SampleSummaryPair) String() string {
	return fmt.Sprintf("%s @[%s]", s.Summary, s.Timestamp)
}

func (s *SampleSummaryPair) Equal(o *SampleSummaryPair) bool {
	return s == o || (s.Summary.Equal(o.Summary) && s.Timestamp.Equal(o.Timestamp))
}
