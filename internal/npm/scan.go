package npm

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Packuments from upstream registries can be hundreds of megabytes, so
// they are read and rewritten as streams, a version at a time: only one
// version's manifest is held at once.

// errNotPackument means a document is not a packument flint can read.
var errNotPackument = errors.New("the document is not a valid packument")

// packumentVisitor receives a packument's fields as scanPackument reads
// them, in the document's order.
type packumentVisitor struct {
	// field, if not nil, receives each top-level field other than
	// versions, with its JSON.
	field func(key string, raw json.RawMessage) error
	// version, if not nil, receives each entry of versions: the version
	// and its manifest's JSON. Without it, versions is passed to field,
	// as it is when it is null.
	version func(ver string, raw json.RawMessage) error
	// versionsStart and versionsEnd, if not nil, are called before the
	// first entry of versions and after the last, when version is set.
	versionsStart, versionsEnd func() error
}

// scanPackument reads a packument, a JSON object whose versions, if
// present, is an object of version manifests, calling v's functions.
func scanPackument(r io.Reader, v packumentVisitor) error {
	dec := json.NewDecoder(bufio.NewReaderSize(r, 64<<10))
	if err := delim(dec, '{'); err != nil {
		return err
	}
	for dec.More() {
		key, err := objectKey(dec)
		if err != nil {
			return err
		}
		if key == "versions" && v.version != nil {
			if err := scanVersions(dec, v); err != nil {
				return err
			}
			continue
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return syntax(err)
		}
		if v.field != nil {
			if err := v.field(key, raw); err != nil {
				return err
			}
		}
	}
	if err := delim(dec, '}'); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("%w: data after the packument", errNotPackument)
	}
	return nil
}

// scanVersions reads the value of versions: an object of manifests, or
// null.
func scanVersions(dec *json.Decoder, v packumentVisitor) error {
	t, err := dec.Token()
	switch {
	case err != nil:
		return syntax(err)
	case t == nil:
		if v.field != nil {
			return v.field("versions", json.RawMessage("null"))
		}
		return nil
	case t != json.Delim('{'):
		return fmt.Errorf("%w: versions is not an object", errNotPackument)
	}
	if v.versionsStart != nil {
		if err := v.versionsStart(); err != nil {
			return err
		}
	}
	for dec.More() {
		ver, err := objectKey(dec)
		if err != nil {
			return err
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return syntax(err)
		}
		if len(raw) == 0 || raw[0] != '{' {
			return fmt.Errorf("%w: version %q is not an object", errNotPackument, abbrev(ver))
		}
		if err := v.version(ver, raw); err != nil {
			return err
		}
	}
	if err := delim(dec, '}'); err != nil {
		return err
	}
	if v.versionsEnd != nil {
		return v.versionsEnd()
	}
	return nil
}

// delim reads a delimiter token, which must be want.
func delim(dec *json.Decoder, want json.Delim) error {
	t, err := dec.Token()
	if err != nil {
		return syntax(err)
	}
	if t != want {
		return fmt.Errorf("%w: want %q", errNotPackument, want)
	}
	return nil
}

// objectKey reads an object's key.
func objectKey(dec *json.Decoder) (string, error) {
	t, err := dec.Token()
	if err != nil {
		return "", syntax(err)
	}
	k, ok := t.(string)
	if !ok {
		return "", fmt.Errorf("%w: want a key", errNotPackument)
	}
	return k, nil
}

// syntax wraps a decoding error, also an unexpected end, as
// errNotPackument.
func syntax(err error) error {
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return fmt.Errorf("%w: %v", errNotPackument, err)
}

// objectWriter writes a JSON object to a stream, a field at a time.
type objectWriter struct {
	w     io.Writer
	err   error
	empty bool
}

func newObjectWriter(w io.Writer) *objectWriter {
	o := &objectWriter{w: w, empty: true}
	o.write([]byte{'{'})
	return o
}

func (o *objectWriter) write(b []byte) {
	if o.err == nil {
		_, o.err = o.w.Write(b)
	}
}

// key starts a field.
func (o *objectWriter) key(k string) {
	if !o.empty {
		o.write([]byte{','})
	}
	o.empty = false
	kb, _ := json.Marshal(k)
	o.write(kb)
	o.write([]byte{':'})
}

// raw writes a field with a JSON value.
func (o *objectWriter) raw(k string, v []byte) {
	o.key(k)
	o.write(v)
}

// close ends the object and returns the first write error.
func (o *objectWriter) close() error {
	o.write([]byte{'}'})
	return o.err
}

// editObject returns the JSON object raw with the fields fn changes: fn
// gets each field and returns its new value, the same value to keep it,
// or nil to drop it. Fields keep their order. A value that is not an
// object is returned as it is.
func editObject(raw json.RawMessage, fn func(key string, val json.RawMessage) (json.RawMessage, error)) (json.RawMessage, error) {
	if len(raw) == 0 || raw[0] != '{' {
		return raw, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := delim(dec, '{'); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	out.Grow(len(raw) + 64)
	o := newObjectWriter(&out)
	for dec.More() {
		k, err := objectKey(dec)
		if err != nil {
			return nil, err
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, syntax(err)
		}
		nv, err := fn(k, v)
		if err != nil {
			return nil, err
		}
		if nv != nil {
			o.raw(k, nv)
		}
	}
	o.close()
	return out.Bytes(), nil
}

// jsonString returns s as a JSON string.
func jsonString(s string) json.RawMessage {
	b, _ := json.Marshal(s)
	return b
}

// rewriteVersion returns version ver of package name, a manifest from an
// upstream packument, with the URLs a client fetches pointing below base,
// a registry URL of flint's: dist.tarball, and dist.attestations.url.
// Everything else is kept, dist.signatures too, which sign the name,
// version, and integrity, not the URLs.
func rewriteVersion(name, ver string, raw json.RawMessage, base string) (json.RawMessage, error) {
	return editObject(raw, func(k string, v json.RawMessage) (json.RawMessage, error) {
		if k != "dist" {
			return v, nil
		}
		return editObject(v, func(k string, v json.RawMessage) (json.RawMessage, error) {
			switch k {
			case "tarball":
				return jsonString(base + name + "/-/" + tarballName(name, ver)), nil
			case "attestations":
				return editObject(v, func(k string, v json.RawMessage) (json.RawMessage, error) {
					if k == "url" {
						return jsonString(base + "-/npm/v1/attestations/" + name + "@" + ver), nil
					}
					return v, nil
				})
			}
			return v, nil
		})
	})
}

// rewritePackument copies an upstream packument of package name from
// src to dst with each version's URLs pointing below base (see
// rewriteVersion), as a stream.
func rewritePackument(dst io.Writer, src io.Reader, name, base string) error {
	bw := bufio.NewWriterSize(dst, 64<<10)
	o := newObjectWriter(bw)
	var versions *objectWriter
	err := scanPackument(src, packumentVisitor{
		field: func(k string, raw json.RawMessage) error {
			o.raw(k, raw)
			return o.err
		},
		versionsStart: func() error {
			o.key("versions")
			versions = newObjectWriter(bw)
			return versions.err
		},
		version: func(ver string, raw json.RawMessage) error {
			nv, err := rewriteVersion(name, ver, raw, base)
			if err != nil {
				return err
			}
			versions.raw(ver, nv)
			return versions.err
		},
		versionsEnd: func() error { return versions.close() },
	})
	if err != nil {
		return err
	}
	if err := o.close(); err != nil {
		return err
	}
	return bw.Flush()
}
