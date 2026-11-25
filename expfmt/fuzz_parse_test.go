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

package expfmt

import (
	"bytes"
	"testing"

	"github.com/prometheus/common/model"
)

// FuzzParseMetricFamilies checks that the line-oriented parser neither panics
// nor returns a half sample, in either mode, for arbitrary input.
func FuzzParseMetricFamilies(f *testing.F) {
	f.Add([]byte("foo 1\nbar{a=\"b\"} 2\n"))
	f.Add([]byte("foo{a=\"1\",a=\"2\"} 1\n"))
	f.Add([]byte("foo{a=\"unterminated} 1\n"))
	f.Add([]byte("foo{a=\"\\q\"} 1\n"))
	f.Add([]byte("foo 1\nbar"))
	f.Add([]byte("foo{a=\"b\"} 1 23\n"))
	f.Add([]byte("# TYPE s summary\ns_sum 1 not-a-ts\n"))

	f.Fuzz(func(t *testing.T, in []byte) {
		for _, mode := range []ParseMode{StrictMode, LenientMode} {
			p := NewTextParser(model.UTF8Validation)
			res, err := p.ParseMetricFamilies(bytes.NewReader(in), mode)
			if mode == StrictMode {
				if err != nil {
					if res.MetricFamilies != nil {
						t.Fatalf("strict mode returned families together with error %v", err)
					}
					continue
				}
			} else if err != nil {
				t.Fatalf("lenient mode returned an error: %v", err)
			}
			// Every returned error must be locatable.
			for _, e := range res.Errors {
				if e.Line < 1 {
					t.Fatalf("error without a line number: %+v", e)
				}
			}
			// Families must never be empty.
			for name, mf := range res.MetricFamilies {
				if len(mf.GetMetric()) == 0 {
					t.Fatalf("returned empty family %q", name)
				}
			}
		}
	})
}
