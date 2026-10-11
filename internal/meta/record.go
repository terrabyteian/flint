package meta

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"time"
)

// On-disk log format. See the package documentation for how recovery uses it.
//
// A segment starts with a 32-byte header:
//
//	magic "flintwal" | format uint32 | salt uint32 | first seq uint64 | reserved uint32 | crc uint32
//
// followed by records:
//
//	length uint32 | crc uint32 | body (length bytes)
//
// The crc is CRC-32C, seeded with the segment's random salt, over the
// length field and the body. The body is
//
//	version uint8 | seq uint64 | uvarint(seq - first seq of its group commit) |
//	varint(commit time, Unix ns) | actor | action | target |
//	uvarint(op count) | ops
//
// where strings are uvarint(length) bytes, and an op is a kind byte (0 put,
// 1 delete), uvarint(length) key, and for a put uvarint(length) value.
// Integers are little endian.

const (
	segMagic       = "flintwal"
	segFormat      = 1
	segHeaderSize  = 32
	recordVersion  = 1
	frameSize      = 8
	minBodySize    = 1 + 8 + 1 + 1 + 3 + 1
	maxBodySize    = 1 << 30
	opPut          = 0
	opDelete       = 1
	defaultMaxBody = 16 << 20
)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

type segHeader struct {
	first Seq
	salt  uint32
}

func appendSegHeader(dst []byte, h segHeader) []byte {
	start := len(dst)
	dst = append(dst, segMagic...)
	dst = binary.LittleEndian.AppendUint32(dst, segFormat)
	dst = binary.LittleEndian.AppendUint32(dst, h.salt)
	dst = binary.LittleEndian.AppendUint64(dst, uint64(h.first))
	dst = binary.LittleEndian.AppendUint32(dst, 0)
	return binary.LittleEndian.AppendUint32(dst, crc32.Checksum(dst[start:], castagnoli))
}

func parseSegHeader(b []byte) (segHeader, error) {
	if len(b) < segHeaderSize {
		return segHeader{}, errors.New("short segment header")
	}
	b = b[:segHeaderSize]
	if string(b[:8]) != segMagic {
		return segHeader{}, errors.New("bad segment magic")
	}
	if crc32.Checksum(b[:28], castagnoli) != binary.LittleEndian.Uint32(b[28:]) {
		return segHeader{}, errors.New("segment header checksum mismatch")
	}
	if f := binary.LittleEndian.Uint32(b[8:]); f != segFormat {
		return segHeader{}, errors.New("unsupported segment format")
	}
	return segHeader{salt: binary.LittleEndian.Uint32(b[12:]), first: Seq(binary.LittleEndian.Uint64(b[16:]))}, nil
}

func appendString(dst []byte, s string) []byte {
	dst = binary.AppendUvarint(dst, uint64(len(s)))
	return append(dst, s...)
}

func appendBytes(dst, s []byte) []byte {
	dst = binary.AppendUvarint(dst, uint64(len(s)))
	return append(dst, s...)
}

// appendRecord appends the framed log record of b, committed as seq in the
// group commit that starts at group.
func appendRecord(dst []byte, salt uint32, seq, group Seq, t time.Time, b *Batch) []byte {
	start := len(dst)
	dst = append(dst, make([]byte, frameSize)...)
	dst = append(dst, recordVersion)
	dst = binary.LittleEndian.AppendUint64(dst, uint64(seq))
	dst = binary.AppendUvarint(dst, uint64(seq-group))
	dst = binary.AppendVarint(dst, t.UnixNano())
	dst = appendString(dst, b.origin.Actor)
	dst = appendString(dst, b.origin.Action)
	dst = appendString(dst, b.origin.Target)
	dst = binary.AppendUvarint(dst, uint64(len(b.ops)))
	for _, op := range b.ops {
		if op.Delete {
			dst = append(dst, opDelete)
			dst = appendBytes(dst, op.Key)
			continue
		}
		dst = append(dst, opPut)
		dst = appendBytes(dst, op.Key)
		dst = appendBytes(dst, op.Value)
	}
	binary.LittleEndian.PutUint32(dst[start:], uint32(len(dst)-start-frameSize))
	crc := crc32.Update(salt, castagnoli, dst[start:start+4])
	crc = crc32.Update(crc, castagnoli, dst[start+frameSize:])
	binary.LittleEndian.PutUint32(dst[start+4:], crc)
	return dst
}

// frameLen returns the body length from a frame header, or -1 if the
// length is implausible.
func frameLen(frame []byte) int {
	n := binary.LittleEndian.Uint32(frame)
	if n < minBodySize || n > maxBodySize {
		return -1
	}
	return int(n)
}

// checkRecord reports whether rec (frame and body) has a valid checksum.
func checkRecord(salt uint32, rec []byte) bool {
	crc := crc32.Update(salt, castagnoli, rec[:4])
	crc = crc32.Update(crc, castagnoli, rec[frameSize:])
	return crc == binary.LittleEndian.Uint32(rec[4:])
}

// recHead is the fixed part of a record body.
type recHead struct {
	seq   Seq
	group Seq // first seq of the record's group commit
}

// parseHead decodes the start of a body. It is cheap, for scanning.
func parseHead(body []byte) (recHead, bool) {
	if len(body) < 10 || body[0] != recordVersion {
		return recHead{}, false
	}
	seq := Seq(binary.LittleEndian.Uint64(body[1:]))
	d, n := binary.Uvarint(body[9:])
	if n <= 0 || d >= uint64(seq) {
		return recHead{}, false
	}
	return recHead{seq: seq, group: seq - Seq(d)}, true
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
// entry's keys and values alias body.
func decodeBody(body []byte) (Entry, error) {
	h, ok := parseHead(body)
	if !ok {
		return Entry{}, errors.New("bad record header")
	}
	d := decoder{b: body[9:]}
	d.uvarint()
	t, n := binary.Varint(d.b)
	if n <= 0 {
		return Entry{}, errors.New("bad record time")
	}
	d.b = d.b[n:]
	e := Entry{Seq: h.seq, Time: time.Unix(0, t)}
	e.Origin.Actor = string(d.bytes())
	e.Origin.Action = string(d.bytes())
	e.Origin.Target = string(d.bytes())
	nops := d.uvarint()
	if d.err || nops > uint64(len(d.b)) {
		return Entry{}, errors.New("bad record origin or op count")
	}
	e.Ops = make([]Op, nops)
	for i := range e.Ops {
		if len(d.b) == 0 {
			return Entry{}, errors.New("truncated op")
		}
		kind := d.b[0]
		d.b = d.b[1:]
		switch kind {
		case opPut:
			e.Ops[i].Key = d.bytes()
			e.Ops[i].Value = d.bytes()
		case opDelete:
			e.Ops[i].Delete = true
			e.Ops[i].Key = d.bytes()
		default:
			return Entry{}, errors.New("bad op kind")
		}
		if d.err {
			return Entry{}, errors.New("truncated op")
		}
	}
	if len(d.b) != 0 {
		return Entry{}, errors.New("trailing bytes in record")
	}
	return e, nil
}
