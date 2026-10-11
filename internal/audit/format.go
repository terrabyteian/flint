package audit

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"time"

	"github.com/terrabyteian/flint/internal/meta"
)

// On-disk format. A segment, audit/<first seq>.audit with the sequence
// number in 20 zero-padded digits, starts with a 32-byte header:
//
//	magic "flintaud" | format uint32 | reserved uint32 | first seq uint64 | reserved uint32 | crc uint32
//
// followed by records:
//
//	length uint32 | crc uint32 | body (length bytes)
//
// The crc is CRC-32C over the length field and the body. The body is
//
//	version uint8 | seq uint64 | varint(commit time, Unix ns) |
//	actor | action | target | client | uvarint(key count) | keys
//
// where strings are uvarint(length) bytes, and a key is a kind byte (0 put,
// 1 delete) and uvarint(length) bytes. Integers are little endian. There
// is no field for a value.

const (
	segMagic      = "flintaud"
	segFormat     = 1
	segHeaderSize = 32
	segExt        = ".audit"
	recordVersion = 1
	frameSize     = 8
	minBodySize   = 1 + 8 + 1 + 4 + 1
	maxBodySize   = 1 << 30
	keyPut        = 0
	keyDelete     = 1
)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// Record is one audited batch: who changed what, and which keys, never
// the values written.
type Record struct {
	Seq    meta.Seq
	Time   time.Time // commit time, from the server's clock
	Actor  string
	Action string
	Target string
	Client string
	Keys   []Key
}

// Key is a key a batch wrote or deleted.
type Key struct {
	Delete bool
	Key    []byte
}

func segName(first meta.Seq) string { return fmt.Sprintf("%020d%s", first, segExt) }

func appendSegHeader(dst []byte, first meta.Seq) []byte {
	start := len(dst)
	dst = append(dst, segMagic...)
	dst = binary.LittleEndian.AppendUint32(dst, segFormat)
	dst = binary.LittleEndian.AppendUint32(dst, 0)
	dst = binary.LittleEndian.AppendUint64(dst, uint64(first))
	dst = binary.LittleEndian.AppendUint32(dst, 0)
	return binary.LittleEndian.AppendUint32(dst, crc32.Checksum(dst[start:], castagnoli))
}

func parseSegHeader(b []byte) (meta.Seq, error) {
	if len(b) < segHeaderSize {
		return 0, errors.New("short segment header")
	}
	b = b[:segHeaderSize]
	switch {
	case string(b[:8]) != segMagic:
		return 0, errors.New("bad segment magic")
	case crc32.Checksum(b[:28], castagnoli) != binary.LittleEndian.Uint32(b[28:]):
		return 0, errors.New("segment header checksum mismatch")
	case binary.LittleEndian.Uint32(b[8:]) != segFormat:
		return 0, errors.New("unsupported segment format")
	}
	return meta.Seq(binary.LittleEndian.Uint64(b[16:])), nil
}

func appendString(dst []byte, s string) []byte {
	dst = binary.AppendUvarint(dst, uint64(len(s)))
	return append(dst, s...)
}

// appendRecord appends the framed record of batch e. It reads e's keys
// and origin only: operation values never reach the stream.
func appendRecord(dst []byte, e *meta.Entry) []byte {
	start := len(dst)
	dst = append(dst, make([]byte, frameSize)...)
	dst = append(dst, recordVersion)
	dst = binary.LittleEndian.AppendUint64(dst, uint64(e.Seq))
	dst = binary.AppendVarint(dst, e.Time.UnixNano())
	dst = appendString(dst, e.Origin.Actor)
	dst = appendString(dst, e.Origin.Action)
	dst = appendString(dst, e.Origin.Target)
	dst = appendString(dst, e.Origin.Client)
	dst = binary.AppendUvarint(dst, uint64(len(e.Ops)))
	for _, op := range e.Ops {
		kind := byte(keyPut)
		if op.Delete {
			kind = keyDelete
		}
		dst = append(dst, kind)
		dst = binary.AppendUvarint(dst, uint64(len(op.Key)))
		dst = append(dst, op.Key...)
	}
	binary.LittleEndian.PutUint32(dst[start:], uint32(len(dst)-start-frameSize))
	crc := crc32.Update(0, castagnoli, dst[start:start+4])
	crc = crc32.Update(crc, castagnoli, dst[start+frameSize:])
	binary.LittleEndian.PutUint32(dst[start+4:], crc)
	return dst
}

type decoder struct {
	b   []byte
	err bool
}

func (d *decoder) uvarint() uint64 {
	v, n := binary.Uvarint(d.b)
	if n <= 0 {
		d.err = true
		d.b = nil
		return 0
	}
	d.b = d.b[n:]
	return v
}

func (d *decoder) bytes() []byte {
	n := d.uvarint()
	if n > uint64(len(d.b)) {
		d.err = true
		d.b = nil
		return nil
	}
	v := d.b[:n:n]
	d.b = d.b[n:]
	return v
}

// decodeBody decodes a record body whose checksum is valid. The returned
// keys alias body.
func decodeBody(body []byte) (Record, error) {
	if len(body) < minBodySize || body[0] != recordVersion {
		return Record{}, errors.New("bad record header")
	}
	rec := Record{Seq: meta.Seq(binary.LittleEndian.Uint64(body[1:]))}
	t, n := binary.Varint(body[9:])
	if n <= 0 {
		return Record{}, errors.New("bad record time")
	}
	rec.Time = time.Unix(0, t)
	d := decoder{b: body[9+n:]}
	rec.Actor = string(d.bytes())
	rec.Action = string(d.bytes())
	rec.Target = string(d.bytes())
	rec.Client = string(d.bytes())
	nkeys := d.uvarint()
	if d.err || nkeys > uint64(len(d.b)) {
		return Record{}, errors.New("bad record origin or key count")
	}
	rec.Keys = make([]Key, nkeys)
	for i := range rec.Keys {
		if len(d.b) == 0 {
			return Record{}, errors.New("truncated key")
		}
		switch d.b[0] {
		case keyPut:
		case keyDelete:
			rec.Keys[i].Delete = true
		default:
			return Record{}, errors.New("bad key kind")
		}
		d.b = d.b[1:]
		rec.Keys[i].Key = d.bytes()
		if d.err {
			return Record{}, errors.New("truncated key")
		}
	}
	if len(d.b) != 0 {
		return Record{}, errors.New("trailing bytes in record")
	}
	return rec, nil
}

// errBadRecord means a record's frame, checksum, or body is invalid.
var errBadRecord = errors.New("bad record")

// recordReader reads framed records from a segment after its header.
type recordReader struct {
	r   *bufio.Reader
	off int64 // offset of the next record in the segment
	end int64 // offset the reader stops at
	buf []byte
}

func newRecordReader(r io.Reader, end int64) *recordReader {
	return &recordReader{r: bufio.NewReaderSize(r, 64<<10), off: segHeaderSize, end: end}
}

// next returns the next record, io.EOF at the end, or an error wrapping
// errBadRecord for an invalid one. The record's keys are valid until the
// next call.
func (rr *recordReader) next() (Record, error) {
	if rr.off >= rr.end {
		return Record{}, io.EOF
	}
	if rr.end-rr.off < frameSize {
		return Record{}, fmt.Errorf("%w: truncated frame", errBadRecord)
	}
	var frame [frameSize]byte
	if _, err := io.ReadFull(rr.r, frame[:]); err != nil {
		return Record{}, readErr(err)
	}
	n := binary.LittleEndian.Uint32(frame[:])
	if n < minBodySize || n > maxBodySize || int64(n) > rr.end-rr.off-frameSize {
		return Record{}, fmt.Errorf("%w: implausible length %d", errBadRecord, n)
	}
	if cap(rr.buf) < int(n) {
		rr.buf = make([]byte, n)
	}
	body := rr.buf[:n]
	if _, err := io.ReadFull(rr.r, body); err != nil {
		return Record{}, readErr(err)
	}
	crc := crc32.Update(0, castagnoli, frame[:4])
	crc = crc32.Update(crc, castagnoli, body)
	if crc != binary.LittleEndian.Uint32(frame[4:]) {
		return Record{}, fmt.Errorf("%w: checksum mismatch", errBadRecord)
	}
	rec, err := decodeBody(body)
	if err != nil {
		return Record{}, fmt.Errorf("%w: %v", errBadRecord, err)
	}
	rr.off += frameSize + int64(n)
	return rec, nil
}

// readErr reports a file that ended before its expected size as a bad
// record, and other read errors as they are.
func readErr(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("%w: truncated record", errBadRecord)
	}
	return err
}

// CorruptionError reports a damaged audit segment. It names the file and
// the byte offset of the problem.
type CorruptionError struct {
	Path   string
	Offset int64
	Reason string
}

func (e *CorruptionError) Error() string {
	return fmt.Sprintf("audit: corrupt data in %s at offset %d: %s", e.Path, e.Offset, e.Reason)
}
