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
	"errors"
	"io"
	"slices"
	"strings"
	"testing"

	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/common/model"
)

func TestParseMetricFamiliesLenientRecovers(t *testing.T) {
	in := `# HELP foo Some help.
# TYPE foo gauge
foo 1
foo{a="1",a="2"} 2
bar{x="unclosed} 3
baz{z="\q"} 4
qux 5
last 6`

	p := NewTextParser(model.UTF8Validation)
	res, err := p.ParseMetricFamilies(strings.NewReader(in), LenientMode)
	require.NoError(t, err)

	// Every good line survives, including the final line without a newline.
	// "baz" only appeared on the invalid line, so it must not show up at all:
	// a failed line leaves no state behind.
	require.Equal(t, []string{"foo", "last", "qux"}, sortedNames(res.MetricFamilies))
	require.NotContains(t, res.MetricFamilies, "baz")
	require.Len(t, res.MetricFamilies["foo"].GetMetric(), 1)
	require.Equal(t, 5.0, res.MetricFamilies["qux"].GetMetric()[0].GetUntyped().GetValue())

	require.Len(t, res.Errors, 3)
	require.Equal(t, []int{4, 5, 6}, errorLines(res.Errors))
	require.Equal(t, []ParseErrorKind{ParseErrorDuplicateLabel, ParseErrorUnclosedQuote, ParseErrorInvalidEscape}, errorKinds(res.Errors))

	// The sentinels are reachable through errors.Is.
	require.ErrorIs(t, res.Errors[0], ErrDuplicateLabel)
	require.ErrorIs(t, res.Errors[1], ErrUnclosedQuote)
	require.ErrorIs(t, res.Errors[2], ErrInvalidEscape)
	require.NotErrorIs(t, res.Errors[2], ErrDuplicateLabel)

	// Every error points into the offending line and quotes its beginning.
	for _, e := range res.Errors {
		require.GreaterOrEqual(t, e.Column, 1)
		require.NotEmpty(t, e.Fragment)
		require.Contains(t, e.Error(), "text format parsing error in line")
	}
	require.Equal(t, `foo{a="1",a="2"} 2`, res.Errors[0].Fragment)
	require.Contains(t, res.Errors[0].Msg, "duplicate label names")
}

func TestParseMetricFamiliesColumn(t *testing.T) {
	in := "ok 1\nmetric{label=\"a\",label=\"b\"} 2\n"
	p := NewTextParser(model.UTF8Validation)
	res, err := p.ParseMetricFamilies(strings.NewReader(in), LenientMode)
	require.NoError(t, err)
	require.Len(t, res.Errors, 1)
	e := res.Errors[0]
	require.Equal(t, 2, e.Line)
	line := "metric{label=\"a\",label=\"b\"} 2"
	secondLabel := strings.Index(line, "label=\"b\"")
	require.Greaterf(t, e.Column, secondLabel, "the column points at or past the repeated label name")
	require.LessOrEqual(t, e.Column, len(line)+1)
	require.Equalf(t, uint8('='), line[e.Column-1], "column is the 1-based byte offset within the line")
}

func TestParseMetricFamiliesStrict(t *testing.T) {
	in := "foo 1\nbad{a=\"1\",a=\"2\"} 2\nbar 3\n"
	p := NewTextParser(model.UTF8Validation)
	res, err := p.ParseMetricFamilies(strings.NewReader(in), StrictMode)
	require.Error(t, err)
	require.Nil(t, res.MetricFamilies)
	require.Empty(t, res.Errors)

	var perr ParseError
	require.ErrorAs(t, err, &perr)
	require.Equal(t, 2, perr.Line)
	require.Equal(t, ParseErrorDuplicateLabel, perr.Kind)
	require.NotEmpty(t, perr.Fragment)
}

func TestParseMetricFamiliesStrictMatchesWholeInput(t *testing.T) {
	inputs := []string{
		"foo 1\nbar 2\n",
		"# HELP foo x\n# TYPE foo gauge\nfoo 1\n",
		"foo 1\nbad{a=\"1\",a=\"2\"} 2\n",
		"foo{a=\"x} 2\n",
	}
	for _, in := range inputs {
		p := NewTextParser(model.UTF8Validation)
		fams, textErr := p.TextToMetricFamilies(strings.NewReader(in))
		res, parseErr := p.ParseMetricFamilies(strings.NewReader(in), StrictMode)
		require.Equalf(t, textErr == nil, parseErr == nil, "input %q", in)
		if textErr != nil {
			require.Equalf(t, textErr.Error(), parseErr.Error(), "input %q", in)
			require.Emptyf(t, res.MetricFamilies, "input %q", in)
			continue
		}
		require.Equalf(t, sortedNames(fams), sortedNames(res.MetricFamilies), "input %q", in)
	}
}

func TestParseMetricFamiliesTruncatedInput(t *testing.T) {
	t.Run("complete final line without newline", func(t *testing.T) {
		p := NewTextParser(model.UTF8Validation)
		res, err := p.ParseMetricFamilies(strings.NewReader("foo 1\nbar 2"), LenientMode)
		require.NoError(t, err)
		require.Empty(t, res.Errors)
		require.Equal(t, []string{"bar", "foo"}, sortedNames(res.MetricFamilies))
	})

	t.Run("cut off mid-sample", func(t *testing.T) {
		p := NewTextParser(model.UTF8Validation)
		res, err := p.ParseMetricFamilies(strings.NewReader("foo 1\nbar{label=\"x\"} 2 "), LenientMode)
		require.NoError(t, err)
		require.Len(t, res.Errors, 1)
		e := res.Errors[0]
		require.Equal(t, ParseErrorTruncatedInput, e.Kind)
		require.ErrorIs(t, e, ErrTruncatedInput)
		require.Equal(t, 2, e.Line)
		// If the input is instead just a valid sample, it must not be reported.
		_, ok := res.MetricFamilies["bar"]
		require.Falsef(t, ok, "a half sample must not be returned")
	})

	t.Run("no half sample with trailing newline", func(t *testing.T) {
		p := NewTextParser(model.UTF8Validation)
		res, err := p.ParseMetricFamilies(strings.NewReader("foo 1\nbar{label=\"x\"} 2"), LenientMode)
		require.NoError(t, err)
		// A complete line without a newline is valid.
		require.Empty(t, res.Errors)
		require.Contains(t, res.MetricFamilies, "bar")
	})
}

func TestParseMetricFamiliesLongLines(t *testing.T) {
	long := "long_metric{a=\"" + strings.Repeat("x", 10000) + "\"} 1\nshort 2\n"
	p := NewTextParser(model.UTF8Validation)
	res, err := p.ParseMetricFamilies(strings.NewReader(long), LenientMode)
	require.NoError(t, err)
	require.Empty(t, res.Errors)
	require.Equal(t, []string{"long_metric", "short"}, sortedNames(res.MetricFamilies))
	require.Equal(t, strings.Repeat("x", 10000),
		res.MetricFamilies["long_metric"].GetMetric()[0].GetLabel()[0].GetValue())
}

func TestParseMetricFamiliesRollback(t *testing.T) {
	t.Run("summary sum with bad timestamp", func(t *testing.T) {
		in := "# TYPE s summary\ns{quantile=\"0.5\"} 1\ns_sum 2 not-a-timestamp\n"
		p := NewTextParser(model.UTF8Validation)
		res, err := p.ParseMetricFamilies(strings.NewReader(in), LenientMode)
		require.NoError(t, err)
		require.Len(t, res.Errors, 1)
		m := res.MetricFamilies["s"].GetMetric()
		require.Len(t, m, 1)
		require.Equalf(t, uint64(0), m[0].GetSummary().GetSampleCount(), "the failed _sum line must be rolled back")
		require.Equal(t, 0.0, m[0].GetSummary().GetSampleSum())
	})

	t.Run("second type line does not change type", func(t *testing.T) {
		in := "# TYPE x gauge\n# TYPE x counter\nx 1\n"
		p := NewTextParser(model.UTF8Validation)
		res, err := p.ParseMetricFamilies(strings.NewReader(in), LenientMode)
		require.NoError(t, err)
		require.Len(t, res.Errors, 1)
		require.Equal(t, dto.MetricType_GAUGE, res.MetricFamilies["x"].GetType())
	})

	t.Run("metadata-only family is dropped", func(t *testing.T) {
		in := "# HELP nobody Some help.\nfoo 1\n"
		p := NewTextParser(model.UTF8Validation)
		res, err := p.ParseMetricFamilies(strings.NewReader(in), LenientMode)
		require.NoError(t, err)
		require.NotContains(t, res.MetricFamilies, "nobody")
	})
}

func TestParseMetricFamiliesReaderError(t *testing.T) {
	boom := errors.New("boom")
	p := NewTextParser(model.UTF8Validation)
	res, err := p.ParseMetricFamilies(&failingReader{data: "foo 1\n", err: boom}, LenientMode)
	require.ErrorIs(t, err, boom)
	// Everything parsed before the reader failed is still returned.
	require.Contains(t, res.MetricFamilies, "foo")
	require.Empty(t, res.Errors)
}

func TestDecoderLenientCompatibility(t *testing.T) {
	in := "a 1\nbad{a=\"1\",a=\"2\"} 2\nb 3\n"

	// The strict decoder keeps its existing behaviour: it eventually reports
	// the malformed line as an error, and callers that stop on the first
	// error see no families before it.
	strict := NewDecoder(strings.NewReader(in), FmtText)
	var mf dto.MetricFamily
	var strictErr error
	for {
		if strictErr = strict.Decode(&mf); strictErr != nil {
			break
		}
	}
	require.Error(t, strictErr)
	require.NotErrorIs(t, strictErr, io.EOF)
	require.Equal(t, ParseErrorDuplicateLabel, mustParseError(t, strictErr).Kind)

	dec := NewDecoderWithMode(strings.NewReader(in), FmtText, LenientMode)
	rep, ok := dec.(ParseErrorReporter)
	require.True(t, ok)

	var names []string
	for {
		var mf dto.MetricFamily
		if err := dec.Decode(&mf); err != nil {
			require.ErrorIs(t, err, io.EOF)
			break
		}
		names = append(names, mf.GetName())
		require.Len(t, mf.GetMetric(), 1)
	}
	// The text decoder yields families in map iteration order.
	slices.Sort(names)
	require.Equal(t, []string{"a", "b"}, names)
	require.Len(t, rep.ParseErrors(), 1)
	require.Equal(t, ParseErrorDuplicateLabel, rep.ParseErrors()[0].Kind)
	require.Equal(t, 2, rep.ParseErrors()[0].Line)
}

func TestParseMetricFamiliesReuse(t *testing.T) {
	p := NewTextParser(model.UTF8Validation)
	res, err := p.ParseMetricFamilies(strings.NewReader("a 1\nbad{a=\"1\",a=\"2\"} 2\nb 3\n"), LenientMode)
	require.NoError(t, err)
	require.Len(t, res.MetricFamilies, 2)
	require.Len(t, res.Errors, 1)

	res, err = p.ParseMetricFamilies(strings.NewReader("c 4\n"), StrictMode)
	require.NoError(t, err)
	require.Equal(t, []string{"c"}, sortedNames(res.MetricFamilies))
	require.Empty(t, res.Errors)

	fams, err := p.TextToMetricFamilies(strings.NewReader("d 5\n"))
	require.NoError(t, err)
	require.Equal(t, []string{"d"}, sortedNames(fams))
}

func TestTruncateFragment(t *testing.T) {
	require.Equal(t, "abc", truncateFragment([]byte("abc\n")))
	require.Equal(t, "abc", truncateFragment([]byte("abc\r\n")))

	long := strings.Repeat("a", maxFragmentBytes+10)
	frag := truncateFragment([]byte(long))
	require.True(t, strings.HasSuffix(frag, "…"))
	require.LessOrEqual(t, len(frag), maxFragmentBytes+len("…"))

	// A multi-byte rune straddling the cut must not be split.
	multi := strings.Repeat("é", maxFragmentBytes)
	frag = truncateFragment([]byte(multi + "\n"))
	require.True(t, strings.HasSuffix(frag, "…"))
	require.Equal(t, maxFragmentBytes, len(frag)-len("…"))
	require.Equal(t, frag, strings.ToValidUTF8(frag, ""))
}

func mustParseError(t *testing.T, err error) ParseError {
	t.Helper()
	var perr ParseError
	require.ErrorAs(t, err, &perr)
	return perr
}

func sortedNames(fams map[string]*dto.MetricFamily) []string {
	names := make([]string, 0, len(fams))
	for name := range fams {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

func errorLines(errs []ParseError) []int {
	lines := make([]int, len(errs))
	for i, e := range errs {
		lines[i] = e.Line
	}
	return lines
}

func errorKinds(errs []ParseError) []ParseErrorKind {
	kinds := make([]ParseErrorKind, len(errs))
	for i, e := range errs {
		kinds[i] = e.Kind
	}
	return kinds
}

type failingReader struct {
	data string
	err  error
	done bool
}

func (r *failingReader) Read(p []byte) (int, error) {
	if r.done {
		return 0, r.err
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	if len(r.data) == 0 {
		r.done = true
	}
	return n, nil
}
