package npm

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/terrabyteian/flint/internal/blob"
)

// Limits on the request bodies that edit packages.
const (
	// maxDocument bounds the JSON of a PUT body other than attachment
	// data: a publish's manifest and readme, or the whole packument npm
	// sends back to deprecate or unpublish a version.
	maxDocument = 32 << 20
	// maxProvenance bounds a provenance bundle.
	maxProvenance = 4 << 20
	// maxSmallBody bounds the other request bodies: a dist-tag, a login,
	// an audit.
	maxSmallBody = 1 << 20
	// maxDepth bounds the nesting of JSON values.
	maxDepth = 256
)

// putBody is a PUT body of a package: a publish, with the new version and
// its tarball in _attachments, or an edited packument. The top-level
// fields other than _attachments are kept as raw JSON; the tarball is
// streamed into a blob store upload as it arrives, hashed on the way, so
// a publish of any size is never held in memory.
type putBody struct {
	fields      map[string]json.RawMessage
	attachments []*attachment
}

// attachment is an entry of a publish's _attachments.
type attachment struct {
	name        string
	contentType string
	length      int64 // as declared, or -1
	// A tarball (".tgz") is in up, size bytes, with its digests.
	up           blob.Upload
	size         int64
	sha512, sha1 []byte
	// Anything else, such as a provenance bundle (".sigstore"), is in
	// data: its value, a JSON string.
	data []byte
	seen bool // data was read
}

// cancel abandons the uploads of uncommitted tarballs.
func (b *putBody) cancel() {
	for _, a := range b.attachments {
		if a.up != nil {
			a.up.Cancel() // a no-op once committed
		}
	}
}

// field decodes the top-level field k into v; it reports false if the
// field is absent or null.
func (b *putBody) field(k string, v any) (bool, error) {
	raw, ok := b.fields[k]
	if !ok || string(raw) == "null" {
		return false, nil
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return false, errorf(http.StatusBadRequest, "the field %s is not valid: %v", k, err)
	}
	return true, nil
}

// readPut reads a PUT body of a package.
func (h *Handler) readPut(ctx context.Context, body io.Reader) (*putBody, error) {
	j := &jsonReader{r: bufio.NewReaderSize(body, 64<<10), limit: maxDocument}
	b := &putBody{fields: map[string]json.RawMessage{}}
	err := j.object(func(k string) error {
		if k == "_attachments" {
			return h.readAttachments(ctx, j, b)
		}
		if _, dup := b.fields[k]; dup {
			return errorf(http.StatusBadRequest, "the field %s appears twice", abbrev(k))
		}
		raw, err := j.value()
		if err != nil {
			return err
		}
		b.fields[k] = raw
		return nil
	})
	if err == nil {
		err = j.end()
	}
	if err != nil {
		b.cancel()
		return nil, bodyError(ctx, err)
	}
	return b, nil
}

// readAttachments reads the _attachments object.
func (h *Handler) readAttachments(ctx context.Context, j *jsonReader, b *putBody) error {
	if c, err := j.peek(); err != nil {
		return err
	} else if c == 'n' {
		_, err := j.value()
		return err
	}
	return j.object(func(name string) error {
		a := &attachment{name: name, length: -1}
		b.attachments = append(b.attachments, a)
		if len(b.attachments) > 2 {
			return errorf(http.StatusBadRequest, "a publish has one tarball and at most one provenance bundle")
		}
		return j.object(func(k string) error {
			switch k {
			case "data":
				if a.seen {
					return errorf(http.StatusBadRequest, "the attachment %s has data twice", abbrev(name))
				}
				a.seen = true
				if strings.HasSuffix(name, ".tgz") {
					return h.readTarball(ctx, j, a)
				}
				s, err := j.stringValue(maxProvenance)
				a.data = []byte(s)
				return err
			case "content_type":
				s, err := j.stringValue(1024)
				a.contentType = s
				return err
			case "length":
				raw, err := j.value()
				if err != nil {
					return err
				}
				if a.length, err = strconv.ParseInt(string(raw), 10, 64); err != nil || a.length < 0 {
					return errorf(http.StatusBadRequest, "the length of the attachment %s is not a number of bytes", abbrev(name))
				}
				return nil
			}
			_, err := j.value()
			return err
		})
	})
}

// readTarball streams an attachment's base64 data into a blob store
// upload, hashing it with sha512 and sha1 on the way.
func (h *Handler) readTarball(ctx context.Context, j *jsonReader, a *attachment) error {
	if c, err := j.next(); err != nil {
		return err
	} else if c != '"' {
		return errorf(http.StatusBadRequest, "the data of the attachment %s is not a base64 string", abbrev(a.name))
	}
	up, err := h.blobs.NewUpload(ctx)
	if err != nil {
		return err
	}
	a.up = up
	s512, s1 := sha512.New(), sha1.New()
	sr := &stringReader{j: j}
	n, err := io.Copy(io.MultiWriter(up, s512, s1), base64.NewDecoder(base64.StdEncoding, sr))
	switch {
	case sr.err != nil:
		return sr.err
	case err != nil && (isCorrupt(err) || errors.Is(err, io.ErrUnexpectedEOF) && sr.done):
		// A string whose length is not a multiple of 4 ends early.
		return errorf(http.StatusBadRequest, "the data of the attachment %s is not valid base64: %v", abbrev(a.name), err)
	case err != nil:
		return err
	}
	a.size, a.sha512, a.sha1 = n, s512.Sum(nil), s1.Sum(nil)
	return nil
}

// isCorrupt reports whether err is a base64 decoding error, rather than a
// failure to write the decoded bytes.
func isCorrupt(err error) bool {
	var ce base64.CorruptInputError
	return errors.As(err, &ce)
}

// bodyError turns a failure to read a request body into the response
// for it.
func bodyError(ctx context.Context, err error) error {
	var he *httpError
	switch {
	case errors.As(err, &he), ctx.Err() != nil:
		return err
	case errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, errSyntax):
		return errorf(http.StatusBadRequest, "the request body is not valid JSON: %v", err)
	case errors.Is(err, errTooLarge):
		return errorf(http.StatusRequestEntityTooLarge, "%v", err)
	}
	var mbe *http.MaxBytesError
	if errors.As(err, &mbe) {
		return errorf(http.StatusRequestEntityTooLarge, "the request body is too large")
	}
	return err
}

// readJSON reads a small request body, at most maxSmallBody bytes, into
// v. A gzip-compressed body, as npm sends with audits, is decompressed
// first, and the bound applies to the decompressed bytes.
func readJSON(w http.ResponseWriter, r *http.Request, v any) error {
	body, err := requestBody(r)
	if err != nil {
		return err
	}
	b, err := io.ReadAll(http.MaxBytesReader(w, body, maxSmallBody))
	if err != nil {
		return bodyError(r.Context(), err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		return errorf(http.StatusBadRequest, "the request body is not valid: %v", err)
	}
	return nil
}

// requestBody returns the request's body, decompressed if its
// Content-Encoding is gzip.
func requestBody(r *http.Request) (io.ReadCloser, error) {
	switch enc := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding"))); enc {
	case "", "identity":
		return r.Body, nil
	case "gzip", "x-gzip":
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			return nil, errorf(http.StatusBadRequest, "the request body is not valid gzip: %v", err)
		}
		return zr, nil
	default:
		return nil, errorf(http.StatusUnsupportedMediaType, "unsupported Content-Encoding %q", abbrev(enc))
	}
}

var (
	errSyntax   = errors.New("invalid JSON")
	errTooLarge = fmt.Errorf("the request body's JSON is larger than %d MiB, not counting attachments", maxDocument>>20)
)

// jsonReader reads JSON from a stream, a value at a time, so a large
// string, such as an attachment's base64 data, can be streamed rather
// than held. Values read whole are counted against limit.
type jsonReader struct {
	r     *bufio.Reader
	n     int64 // bytes of values read whole
	limit int64
	depth int
}

func syntaxf(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{errSyntax}, args...)...)
}

// eof turns io.EOF in the middle of a value into io.ErrUnexpectedEOF.
func eof(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}

// peek returns the next byte that is not whitespace, without reading it.
func (j *jsonReader) peek() (byte, error) {
	for {
		b, err := j.r.Peek(1)
		if err != nil {
			return 0, eof(err)
		}
		switch b[0] {
		case ' ', '\t', '\n', '\r':
			j.r.Discard(1)
		default:
			return b[0], nil
		}
	}
}

// next reads the next byte that is not whitespace.
func (j *jsonReader) next() (byte, error) {
	c, err := j.peek()
	if err == nil {
		j.r.Discard(1)
	}
	return c, err
}

// end checks that nothing but whitespace follows the value read.
func (j *jsonReader) end() error {
	if _, err := j.peek(); err != io.ErrUnexpectedEOF {
		if err != nil {
			return err
		}
		return syntaxf("data after the top-level value")
	}
	return nil
}

// count adds n bytes to the bytes read whole.
func (j *jsonReader) count(n int) error {
	if j.n += int64(n); j.n > j.limit {
		return errTooLarge
	}
	return nil
}

// object reads an object, calling fn with each key; fn must read the
// key's value.
func (j *jsonReader) object(fn func(key string) error) error {
	if c, err := j.next(); err != nil {
		return err
	} else if c != '{' {
		return syntaxf("want an object")
	}
	if j.depth++; j.depth > maxDepth {
		return syntaxf("nested too deeply")
	}
	defer func() { j.depth-- }()
	for first := true; ; first = false {
		c, err := j.next()
		if err != nil {
			return err
		}
		if c == '}' && first {
			return nil
		}
		if c != '"' {
			return syntaxf("want a key")
		}
		k, err := j.str(int(j.limit - j.n))
		if err == nil {
			err = j.count(len(k))
		}
		if err != nil {
			return err
		}
		if c, err := j.next(); err != nil {
			return err
		} else if c != ':' {
			return syntaxf("want ':' after a key")
		}
		if err := fn(k); err != nil {
			return err
		}
		switch c, err := j.next(); {
		case err != nil:
			return err
		case c == '}':
			return nil
		case c != ',':
			return syntaxf("want ',' or '}' in an object")
		}
	}
}

// stringValue reads a value that must be a string of at most max bytes.
func (j *jsonReader) stringValue(max int) (string, error) {
	if c, err := j.next(); err != nil {
		return "", err
	} else if c != '"' {
		return "", syntaxf("want a string")
	}
	str, err := j.str(min(max, int(j.limit-j.n)))
	if err == nil {
		err = j.count(len(str))
	}
	return str, err
}

// str reads the rest of a string, after its opening quote, unescaped,
// and fails if it is longer than max bytes. Callers count it against the
// limit.
func (j *jsonReader) str(max int) (string, error) {
	var b bytes.Buffer
	sr := &stringReader{j: j}
	buf := make([]byte, 4096)
	for {
		n, err := sr.Read(buf)
		b.Write(buf[:n])
		if b.Len() > max {
			if max >= int(j.limit-j.n) {
				return "", errTooLarge
			}
			return "", errorf(http.StatusRequestEntityTooLarge, "a string in the request body is longer than %d bytes", max)
		}
		if err == io.EOF {
			return b.String(), nil
		}
		if err != nil {
			return "", err
		}
	}
}

// value reads a whole value and returns its JSON, which it counts against
// the limit.
func (j *jsonReader) value() (json.RawMessage, error) {
	var out bytes.Buffer
	if err := j.copyValue(&out); err != nil {
		return nil, err
	}
	if err := j.count(out.Len()); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// copyValue copies a value's JSON to out.
func (j *jsonReader) copyValue(out *bytes.Buffer) error {
	if out.Len() > int(j.limit-j.n) {
		return errTooLarge
	}
	c, err := j.next()
	if err != nil {
		return err
	}
	switch {
	case c == '"':
		s, err := j.str(int(j.limit-j.n) - out.Len())
		if err != nil {
			return err
		}
		b, _ := json.Marshal(s)
		out.Write(b)
		return nil
	case c == '{' || c == '[':
		if j.depth++; j.depth > maxDepth {
			return syntaxf("nested too deeply")
		}
		defer func() { j.depth-- }()
		closer := byte('}')
		if c == '[' {
			closer = ']'
		}
		out.WriteByte(c)
		for first := true; ; first = false {
			c, err := j.peek()
			if err != nil {
				return err
			}
			if c == closer && first {
				j.r.Discard(1)
				out.WriteByte(c)
				return nil
			}
			if closer == '}' {
				if c != '"' {
					return syntaxf("want a key")
				}
				if err := j.copyValue(out); err != nil {
					return err
				}
				if c, err := j.next(); err != nil {
					return err
				} else if c != ':' {
					return syntaxf("want ':' after a key")
				}
				out.WriteByte(':')
			}
			if err := j.copyValue(out); err != nil {
				return err
			}
			if int64(out.Len()) > j.limit-j.n {
				return errTooLarge
			}
			c, err = j.next()
			switch {
			case err != nil:
				return err
			case c == closer:
				out.WriteByte(c)
				return nil
			case c != ',':
				return syntaxf("want ',' or %q", closer)
			}
			out.WriteByte(',')
		}
	case c == '-' || c >= '0' && c <= '9' || c == 't' || c == 'f' || c == 'n':
		lit := []byte{c}
		for {
			b, err := j.r.Peek(1)
			if err == io.EOF {
				break
			} else if err != nil {
				return err
			}
			if !(b[0] >= '0' && b[0] <= '9' || b[0] >= 'a' && b[0] <= 'z' || b[0] == '.' || b[0] == '+' || b[0] == '-' || b[0] == 'E') {
				break
			}
			if len(lit) > 64 {
				return syntaxf("a number or literal is too long")
			}
			lit = append(lit, b[0])
			j.r.Discard(1)
		}
		if !json.Valid(lit) {
			return syntaxf("invalid literal %q", lit)
		}
		out.Write(lit)
		return nil
	}
	return syntaxf("unexpected %q", c)
}

// stringReader reads the rest of a JSON string, after its opening quote,
// unescaped, up to its closing quote, where it returns io.EOF.
type stringReader struct {
	j       *jsonReader
	pending []byte // unescaped bytes not yet returned
	done    bool
	err     error // a syntax error, also reported to io.Copy's caller
}

func (s *stringReader) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if len(s.pending) > 0 {
			c := copy(p[n:], s.pending)
			s.pending = s.pending[c:]
			n += c
			continue
		}
		if s.done {
			break
		}
		if _, err := s.j.r.Peek(1); err != nil {
			s.err = eof(err)
			return n, s.err
		}
		buf, _ := s.j.r.Peek(s.j.r.Buffered())
		avail := len(p) - n
		run := 0
		for run < len(buf) && run < avail && buf[run] != '"' && buf[run] != '\\' && buf[run] >= 0x20 {
			run++
		}
		copy(p[n:], buf[:run])
		s.j.r.Discard(run)
		n += run
		if run == avail || run == len(buf) {
			continue // p is full, or more must be buffered
		}
		switch c := buf[run]; {
		case c == '"':
			s.j.r.Discard(1)
			s.done = true
		case c == '\\':
			s.j.r.Discard(1)
			if err := s.escape(); err != nil {
				s.err = err
				return n, err
			}
		default:
			s.err = syntaxf("a control character in a string")
			return n, s.err
		}
	}
	if n == 0 && s.done {
		return 0, io.EOF
	}
	return n, nil
}

// escape reads an escape sequence after its backslash into pending.
func (s *stringReader) escape() error {
	c, err := s.j.r.ReadByte()
	if err != nil {
		return eof(err)
	}
	switch c {
	case '"', '\\', '/':
		s.pending = append(s.pending[:0], c)
	case 'b':
		s.pending = append(s.pending[:0], '\b')
	case 'f':
		s.pending = append(s.pending[:0], '\f')
	case 'n':
		s.pending = append(s.pending[:0], '\n')
	case 'r':
		s.pending = append(s.pending[:0], '\r')
	case 't':
		s.pending = append(s.pending[:0], '\t')
	case 'u':
		r, err := s.hex4()
		if err != nil {
			return err
		}
		if utf16.IsSurrogate(r) {
			// A surrogate pair is two escapes; a lone surrogate is U+FFFD.
			if b, err := s.j.r.Peek(2); err == nil && b[0] == '\\' && b[1] == 'u' {
				s.j.r.Discard(2)
				r2, err := s.hex4()
				if err != nil {
					return err
				}
				if dec := utf16.DecodeRune(r, r2); dec != utf8.RuneError {
					r = dec
				} else {
					s.pending = utf8.AppendRune(s.pending[:0], utf8.RuneError)
					r = r2
					if utf16.IsSurrogate(r) {
						r = utf8.RuneError
					}
					s.pending = utf8.AppendRune(s.pending, r)
					return nil
				}
			} else {
				r = utf8.RuneError
			}
		}
		s.pending = utf8.AppendRune(s.pending[:0], r)
	default:
		return syntaxf("invalid escape \\%c", c)
	}
	return nil
}

func (s *stringReader) hex4() (rune, error) {
	var b [4]byte
	if _, err := io.ReadFull(s.j.r, b[:]); err != nil {
		return 0, eof(err)
	}
	v, err := strconv.ParseUint(string(b[:]), 16, 32)
	if err != nil {
		return 0, syntaxf("invalid escape \\u%s", b[:])
	}
	return rune(v), nil
}
