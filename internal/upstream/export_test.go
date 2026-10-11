package upstream

// Exported for tests.
var (
	EncodeDocRecord  = func(d *DocRecord) []byte { return d.encode() }
	EncodeFileRecord = func(f *FileRecord) []byte { return f.encode() }
)
