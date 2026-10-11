package meta

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

// TestDecodeRecordV1 checks that records written before the origin had a
// client still decode.
func TestDecodeRecordV1(t *testing.T) {
	var b Batch
	b.Put([]byte("k"), []byte("v"))
	b.Delete([]byte("gone"))
	b.SetOrigin(Origin{Actor: "alice", Action: "test.put", Target: "t"})
	rec := appendRecord(nil, 0, 7, 7, time.Unix(1700000000, 0), &b)
	body := rec[frameSize:]

	// Rewrite the body as version 1: drop the empty client string.
	d := decoder{b: body[9:]}
	d.uvarint() // group offset, one byte here
	_, n := binary.Varint(d.b)
	d.b = d.b[n:]
	for range 3 {
		d.bytes()
	}
	at := len(body) - len(d.b)
	if body[at] != 0 {
		t.Fatalf("client length byte = %d, want 0", body[at])
	}
	v1 := append(append([]byte{recordV1}, body[1:at]...), body[at+1:]...)

	for _, tc := range []struct {
		name   string
		body   []byte
		client string
	}{
		{"v1", v1, ""},
		{"v2", bytes.Clone(body), ""},
	} {
		e, err := decodeBody(tc.body)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if e.Seq != 7 || e.Origin != (Origin{"alice", "test.put", "t", tc.client}) || len(e.Ops) != 2 ||
			string(e.Ops[0].Key) != "k" || string(e.Ops[0].Value) != "v" || !e.Ops[1].Delete {
			t.Fatalf("%s: decoded %+v", tc.name, e)
		}
	}
	bad := bytes.Clone(v1)
	bad[0] = 3
	if _, err := decodeBody(bad); err == nil {
		t.Fatal("decoded a record of an unknown version")
	}
}
