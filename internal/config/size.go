package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// sizeUnits are the units a size may carry: decimal (kB = 1000 bytes) and
// binary (KiB = 1024 bytes), with or without the trailing B, as in
// Kubernetes quantities.
var sizeUnits = map[string]float64{
	"": 1, "B": 1,
	"k": 1e3, "K": 1e3, "kB": 1e3, "KB": 1e3,
	"M": 1e6, "MB": 1e6,
	"G": 1e9, "GB": 1e9,
	"T": 1e12, "TB": 1e12,
	"P": 1e15, "PB": 1e15,
	"Ki": 1 << 10, "KiB": 1 << 10,
	"Mi": 1 << 20, "MiB": 1 << 20,
	"Gi": 1 << 30, "GiB": 1 << 30,
	"Ti": 1 << 40, "TiB": 1 << 40,
	"Pi": 1 << 50, "PiB": 1 << 50,
}

const sizeRule = `use a number of bytes or a number with a unit, such as "500MiB", "20GiB", or "1TB"`

// ParseSize parses a size in bytes: a non-negative number, optionally
// followed by a unit such as "MB", "GiB", or "Ti". Fractions are allowed
// with a unit, as in "1.5GiB".
func ParseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	i := 0
	for i < len(s) && (s[i] >= '0' && s[i] <= '9' || s[i] == '.') {
		i++
	}
	num, unit := s[:i], strings.TrimSpace(s[i:])
	mult, ok := sizeUnits[unit]
	if num == "" || !ok {
		return 0, fmt.Errorf("%q is not a size: %s", s, sizeRule)
	}
	v, err := strconv.ParseFloat(num, 64)
	if err != nil {
		return 0, fmt.Errorf("%q is not a size: %s", s, sizeRule)
	}
	b := v * mult
	if b >= math.MaxInt64 {
		return 0, fmt.Errorf("%q is too large", s)
	}
	return int64(b), nil
}

// ByteSize is a size in bytes, written in JSON as a number of bytes or a
// string such as "20GiB".
type ByteSize struct {
	Bytes int64
	set   bool
	// invalid describes a JSON value that is not a size, for Validate to
	// report with the field's path.
	invalid string
}

// IsZero reports whether the size was not set, for omitzero.
func (b ByteSize) IsZero() bool { return !b.set && b.invalid == "" }

// UnmarshalJSON parses a number of bytes or a size string.
func (b *ByteSize) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		var n json.Number
		if err := json.Unmarshal(data, &n); err != nil {
			*b = ByteSize{invalid: fmt.Sprintf("%s is not a size: %s", data, sizeRule)}
			return nil
		}
		s = n.String()
	}
	v, err := ParseSize(s)
	if err != nil {
		*b = ByteSize{invalid: err.Error()}
		return nil
	}
	*b = ByteSize{Bytes: v, set: true}
	return nil
}

// MarshalJSON writes the size as a number of bytes.
func (b ByteSize) MarshalJSON() ([]byte, error) { return json.Marshal(b.Bytes) }

// FreeSpace is a free-space threshold: a percentage of a filesystem's
// size, such as "5%", or a size, such as "20GiB".
type FreeSpace struct {
	// Percent is the threshold as a percentage of the filesystem's size;
	// it applies when Bytes is 0.
	Percent float64
	// Bytes is the threshold as a size.
	Bytes int64
	text  string
	// invalid describes a JSON value that is not a threshold.
	invalid string
}

// ParseFreeSpace parses a percentage, such as "5%", or a size.
func ParseFreeSpace(s string) (FreeSpace, error) {
	if num, ok := strings.CutSuffix(strings.TrimSpace(s), "%"); ok {
		p, err := strconv.ParseFloat(strings.TrimSpace(num), 64)
		if err != nil || p < 0 || p >= 100 || math.IsNaN(p) {
			return FreeSpace{}, fmt.Errorf("%q is not a percentage from 0%% to below 100%%", s)
		}
		return FreeSpace{Percent: p, text: s}, nil
	}
	b, err := ParseSize(s)
	if err != nil {
		return FreeSpace{}, errors.New(strings.Replace(err.Error(), "use a number", `use a percentage such as "5%", a number`, 1))
	}
	return FreeSpace{Bytes: b, text: s}, nil
}

// IsZero reports whether the threshold was not set, for omitzero.
func (f FreeSpace) IsZero() bool { return f.text == "" && f.invalid == "" }

// String returns the threshold as written.
func (f FreeSpace) String() string { return f.text }

// Of returns the threshold in bytes for a filesystem of total bytes.
func (f FreeSpace) Of(total uint64) uint64 {
	if f.Bytes > 0 || f.Percent == 0 {
		return uint64(f.Bytes)
	}
	return uint64(float64(total) * f.Percent / 100)
}

// UnmarshalJSON parses a percentage or size string, or a number of bytes.
func (f *FreeSpace) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		var n json.Number
		if err := json.Unmarshal(data, &n); err != nil {
			*f = FreeSpace{invalid: fmt.Sprintf(`%s is not a percentage such as "5%%" or a size such as "20GiB"`, data)}
			return nil
		}
		s = n.String()
	}
	v, err := ParseFreeSpace(s)
	if err != nil {
		*f = FreeSpace{invalid: err.Error()}
		return nil
	}
	*f = v
	return nil
}

// MarshalJSON writes the threshold as written.
func (f FreeSpace) MarshalJSON() ([]byte, error) { return json.Marshal(f.text) }
