package npm

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"time"
)

func e2eTime(n int) time.Time { return time.Date(2026, 1, n, 0, 0, 0, 0, time.UTC) }

func TestNames(t *testing.T) {
	for _, c := range []struct {
		name       string
		valid, new bool
	}{
		{"lodash", true, true},
		{"@babel/core", true, true},
		{"a.b_c-d", true, true},
		{"-leading-dash", true, true},
		{"JSONStream", true, false},
		{"@Scope/x", true, false},
		{"with(parens)", true, false},
		{"", false, false},
		{".dot", false, false},
		{"_under", false, false},
		{"@scope/.dot", false, false},
		{"@scope", false, false},
		{"@/x", false, false},
		{"a/b", false, false},
		{"@a/b/c", false, false},
		{"sp ace", false, false},
		{"pct%20", false, false},
		{"-", false, false},
		{"node_modules", false, false},
		{"favicon.ico", false, false},
		{strings.Repeat("a", 214), true, true},
		{strings.Repeat("a", 215), false, false},
	} {
		if got := ValidName(c.name); got != c.valid {
			t.Errorf("ValidName(%q) = %v", c.name, got)
		}
		if got := ValidNewName(c.name); got != c.new {
			t.Errorf("ValidNewName(%q) = %v", c.name, got)
		}
	}
}

func TestVersions(t *testing.T) {
	for _, s := range []string{"1.2.3", "0.0.0", "10.20.30", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-0.3.7", "1.0.0-x-y.z"} {
		if _, ok := parseVersion(s); !ok {
			t.Errorf("%q does not parse", s)
		}
	}
	for _, s := range []string{"", "1", "1.2", "1.2.3.4", "v1.2.3", "01.2.3", "1.02.3", "1.2.3-", "1.2.3-a..b", "1.2.3-01",
		"1.2.3+build", "1.2.3-a_b", " 1.2.3", "1.2.3-é", "99999999999999999999.0.0"} {
		if _, ok := parseVersion(s); ok {
			t.Errorf("%q parses", s)
		}
	}
	order := []string{"1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11",
		"1.0.0-rc.1", "1.0.0", "1.0.1", "1.1.0", "2.0.0", "10.0.0"}
	shuffled := slices.Clone(order)
	slices.Reverse(shuffled)
	slices.SortFunc(shuffled, compareVersions)
	if !slices.Equal(shuffled, order) {
		t.Errorf("sorted %v", shuffled)
	}
	if compareVersions("bad", "1.0.0") >= 0 || compareVersions("1.0.0", "1.0.0") != 0 {
		t.Error("compareVersions orders unparsable versions after valid ones")
	}
}

func TestTags(t *testing.T) {
	for _, s := range []string{"latest", "next", "beta", "v-next", "lts.2024", "Canary_1"} {
		if !validTag(s) {
			t.Errorf("%q is not a tag", s)
		}
	}
	for _, s := range []string{"", "1.0.0", "1", "v1", "V2.x", "x", "X.x", "-a", "a b", "a/b", "é", strings.Repeat("a", 129)} {
		if validTag(s) {
			t.Errorf("%q is a tag", s)
		}
	}
}

func TestTarballNames(t *testing.T) {
	for _, c := range []struct {
		name, file, version string
		ok                  bool
	}{
		{"p", "p-1.0.0.tgz", "1.0.0", true},
		{"p", "p-1.0.0-rc.1.tgz", "1.0.0-rc.1", true},
		{"@s/p", "p-1.0.0.tgz", "1.0.0", true},
		{"@s/p", "@s/p-1.0.0.tgz", "1.0.0", true},
		{"p", "p-1.0.tgz", "", false},
		{"p", "q-1.0.0.tgz", "", false},
		{"p", "p-1.0.0.tar.gz", "", false},
		{"p-q", "p-q-1.0.0.tgz", "1.0.0", true},
		{"p", "p-q-1.0.0.tgz", "", false},
	} {
		v, ok := tarballVersion(c.name, c.file)
		if v != c.version || ok != c.ok {
			t.Errorf("tarballVersion(%q, %q) = %q, %v", c.name, c.file, v, ok)
		}
	}
	if got := tarballName("@s/p", "1.0.0"); got != "p-1.0.0.tgz" {
		t.Errorf("tarballName = %q", got)
	}
}

func TestPaths(t *testing.T) {
	for _, c := range []struct {
		path, name, rest string
		ok               bool
	}{
		{"p", "p", "", true},
		{"p/1.0.0", "p", "1.0.0", true},
		{"p/-/p-1.0.0.tgz", "p", "-/p-1.0.0.tgz", true},
		{"@s/p", "@s/p", "", true},
		{"@s/p/-rev/3-x", "@s/p", "-rev/3-x", true},
		{"@s", "", "", false},
	} {
		name, rest, ok := splitName(c.path)
		if name != c.name || rest != c.rest || ok != c.ok {
			t.Errorf("splitName(%q) = %q, %q, %v", c.path, name, rest, ok)
		}
	}
	for _, c := range []struct {
		path, name, file, rev string
		ok                    bool
	}{
		{"p/-/p-1.0.0.tgz/-rev/3-x", "p", "p-1.0.0.tgz", "3-x", true},
		{"@s/p/-/p-1.0.0.tgz/-rev/3-x", "@s/p", "p-1.0.0.tgz", "3-x", true},
		{"npm/local/@s/p/-/p-1.0.0.tgz/-rev/3-x", "@s/p", "p-1.0.0.tgz", "3-x", true},
		{"flint/npm/local/p/-/p-1.0.0.tgz/-rev/3-x", "p", "p-1.0.0.tgz", "3-x", true},
		{"p/-rev/3-x", "", "", "", false},
		{"p/-/p-1.0.0.tgz/-rev/", "", "", "", false},
		{"p/-/a/b/-rev/1", "", "", "", false},
	} {
		name, file, rev, ok := tarballDeletePath(c.path)
		if ok != c.ok || ok && (name != c.name || file != c.file || rev != c.rev) {
			t.Errorf("tarballDeletePath(%q) = %q, %q, %q, %v", c.path, name, file, rev, ok)
		}
	}
	for _, c := range []struct {
		rev  string
		want uint64
	}{{"12-abc", 12}, {"12", 12}, {"x-1", 0}, {"", 0}, {"-1", 0}} {
		if got := parseRev(c.rev); uint64(got) != c.want {
			t.Errorf("parseRev(%q) = %d", c.rev, got)
		}
	}
}

// TestJSONReader checks the streaming JSON reader against encoding/json.
func TestJSONReader(t *testing.T) {
	for _, in := range []string{
		`{}`, `{"a": 1}`, ` { "a" : [1, 2.5e3, -0, true, false, null, "s", {"b": []}] , "c": {} } `,
		`{"esc": "\"\\\/\b\f\n\r\tAé😀 \udc00 \ud800x"}`,
		`{"nested": [[[[{"x": [{}]}]]]]}`,
	} {
		j := &jsonReader{r: bufio.NewReaderSize(strings.NewReader(in), 16), limit: 1 << 20}
		got := map[string]json.RawMessage{}
		err := j.object(func(k string) error {
			v, err := j.value()
			got[k] = v
			return err
		})
		if err == nil {
			err = j.end()
		}
		if err != nil {
			t.Errorf("%s: %v", in, err)
			continue
		}
		var want map[string]any
		json.Unmarshal([]byte(in), &want)
		gb, _ := json.Marshal(got)
		var g map[string]any
		if err := json.Unmarshal(gb, &g); err != nil {
			t.Errorf("%s: read %s: %v", in, gb, err)
			continue
		}
		if wb, _ := json.Marshal(want); !bytes.Equal(wb, mustJSON(g)) {
			t.Errorf("%s: read %s, want %s", in, mustJSON(g), wb)
		}
	}
	for _, in := range []string{`{"a": 01}`, `{"a": 1.}`, `{"a": [}`, `{"a" 1}`, `{a: 1}`, `{"a": "x`, `{"a": "\u12"}`,
		`{"a": ` + strings.Repeat("[", maxDepth+1) + strings.Repeat("]", maxDepth+1) + `}`} {
		j := &jsonReader{r: bufio.NewReader(strings.NewReader(in)), limit: 1 << 20}
		err := j.object(func(string) error { _, err := j.value(); return err })
		if err == nil {
			t.Errorf("%s: no error", in)
		}
	}
	// Values past the limit are refused before they are held.
	j := &jsonReader{r: bufio.NewReader(strings.NewReader(`{"a": "` + strings.Repeat("x", 100) + `"}`)), limit: 50}
	if err := j.object(func(string) error { _, err := j.value(); return err }); !errors.Is(err, errTooLarge) {
		t.Errorf("a long string: %v", err)
	}
	j = &jsonReader{r: bufio.NewReader(strings.NewReader(`{"a": [` + strings.Repeat("1,", 100) + `1]}`)), limit: 50}
	if err := j.object(func(string) error { _, err := j.value(); return err }); !errors.Is(err, errTooLarge) {
		t.Errorf("a long array: %v", err)
	}
}

// TestStringReader checks that a string streams in small reads.
func TestStringReader(t *testing.T) {
	in := strings.Repeat(`ab\"cé`, 1000) + `" tail`
	j := &jsonReader{r: bufio.NewReaderSize(strings.NewReader(in), 16)}
	sr := &stringReader{j: j}
	var out bytes.Buffer
	buf := make([]byte, 3)
	for {
		n, err := sr.Read(buf)
		out.Write(buf[:n])
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if want := strings.Repeat(`ab"cé`, 1000); out.String() != want {
		t.Errorf("read %q", out.String()[:40])
	}
	if rest, _ := io.ReadAll(j.r); string(rest) != " tail" {
		t.Errorf("left %q", rest)
	}
}
