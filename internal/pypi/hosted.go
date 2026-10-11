package pypi

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/terrabyteian/flint/internal/blake2b"
	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/gc"
	"github.com/terrabyteian/flint/internal/meta"
)

// hostedProject returns the live files of a hosted project, or nil if it
// has none.
func hostedProject(v meta.View, rp *repository, project string) (*projectDoc, error) {
	if _, ok := v.Get(projectKey(rp.name, project)); !ok {
		return nil, nil
	}
	p := &projectDoc{Format: pageFormat, Name: project}
	pfx := indexPrefix(rp.name, project)
	var failure error
	v.Scan(pfx, nil, func(k []byte, _ meta.Record) bool {
		filename := string(k[len(pfx):])
		rec, ok := v.Get(fileKey(rp.name, filename))
		if !ok {
			return true
		}
		f, err := decodeFile(rec.Value)
		if err != nil {
			failure = fmt.Errorf("pypi: file record of %s in %s: %w", filename, rp.name, err)
			return false
		}
		if f.Kind == kindHosted {
			p.Files = append(p.Files, hostedEntry(rp, filename, f))
		}
		return true
	})
	if failure != nil || len(p.Files) == 0 {
		return nil, failure
	}
	p.finish()
	return p, nil
}

// hostedEntry lists a hosted file.
func hostedEntry(rp *repository, filename string, f *fileRecord) *file {
	e := &file{
		Filename: filename, Version: f.Version, SHA256: f.Digest.Hex(), MD5: hex.EncodeToString(f.MD5),
		Blake2b256: hex.EncodeToString(f.Blake2b), Size: f.Size, UploadTime: f.Uploaded,
		RequiresPython: f.RequiresPython, Yanked: f.Yanked, YankedReason: f.YankedReason,
		Metadata: f.MetaServed, src: rp, rec: f,
	}
	if f.MetaServed {
		e.MetadataSHA256 = f.Meta.Hex()
	}
	return e
}

// hostedFile returns the record of a live hosted file of project.
func hostedFile(v meta.View, rp *repository, project, filename string) (*fileRecord, error) {
	rec, ok := v.Get(fileKey(rp.name, filename))
	if !ok {
		return nil, errorf(http.StatusNotFound, "%s is not found", filename)
	}
	f, err := decodeFile(rec.Value)
	if err != nil {
		return nil, err
	}
	if f.Kind != kindHosted || f.Project != project {
		return nil, errorf(http.StatusNotFound, "%s is not found", filename)
	}
	return f, nil
}

// owns reports whether hosted repository name owns project: a file of it
// was ever uploaded there.
func owns(v meta.View, name, project string) bool {
	_, ok := v.Get(projectKey(name, project))
	return ok
}

// Upload limits.
const (
	// maxFormField bounds one upload form field, such as the description.
	maxFormField = 8 << 20
	// maxForm bounds all upload form fields together.
	maxForm = 32 << 20
	// maxFormParts bounds the parts of an upload form.
	maxFormParts = 4096
)

// upload is a parsed upload request.
type upload struct {
	form     map[string][]string
	filename string
	up       blob.Upload
	md5      hash.Hash
	blake    hash.Hash
}

// serveUpload serves POST /pypi/<repo>/legacy/, the legacy upload API
// that twine and uv publish use: a multipart form with the file in the
// "content" part and its metadata in the other fields.
func (h *Handler) serveUpload(w http.ResponseWriter, r *http.Request, rp *repository) {
	switch rp.typ {
	case config.TypeProxy:
		writeError(w, http.StatusMethodNotAllowed,
			"repository %s is a read-only proxy of %s; upload to a hosted repository instead", rp.name, rp.proxy.index)
		return
	case config.TypeVirtual:
		writeError(w, http.StatusMethodNotAllowed,
			"repository %s is a virtual repository; upload to one of its hosted members: %s",
			rp.name, strings.Join(rp.virtual.Hosted(), ", "))
		return
	}
	if !h.permit(w, r, rp, ActionPull, ActionPush) {
		return
	}
	u, err := h.readUpload(r)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	created, err := h.storeUpload(r, rp, u)
	if u.up != nil {
		u.up.Cancel() // a no-op once committed
	}
	if err != nil {
		h.fail(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if !created {
		// PyPI answers a repeated upload of the same file with success,
		// so a retried upload is harmless.
		io.WriteString(w, "OK: the file was already uploaded\n")
		return
	}
	io.WriteString(w, "OK\n")
}

// readUpload reads the upload form, streaming the file into a blob store
// upload whatever the order of the parts.
func (h *Handler) readUpload(r *http.Request) (*upload, error) {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "multipart/form-data" {
		return nil, errorf(http.StatusBadRequest, "an upload must be a multipart/form-data request")
	}
	mr, err := r.MultipartReader()
	if err != nil {
		return nil, errorf(http.StatusBadRequest, "invalid upload: %v", err)
	}
	u := &upload{form: map[string][]string{}}
	total := 0
	fail := func(err error) (*upload, error) {
		if u.up != nil {
			u.up.Cancel()
		}
		return nil, err
	}
	for parts := 0; ; parts++ {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fail(errorf(http.StatusBadRequest, "invalid upload form: %v", err))
		}
		if parts >= maxFormParts {
			return fail(errorf(http.StatusBadRequest, "the upload form has too many parts"))
		}
		name := p.FormName()
		switch {
		case name == "content":
			if u.up != nil {
				return fail(errorf(http.StatusBadRequest, "the upload has more than one file"))
			}
			u.filename = p.FileName()
			if u.up, err = h.blobs.NewUpload(r.Context()); err != nil {
				return fail(err)
			}
			u.md5, u.blake = md5.New(), blake2b.New256()
			if _, err := io.Copy(io.MultiWriter(u.up, u.md5, u.blake), p); err != nil {
				if r.Context().Err() != nil {
					return fail(r.Context().Err())
				}
				return fail(errorf(http.StatusBadRequest, "reading the uploaded file: %v", err))
			}
		case p.FileName() != "":
			// Other files, such as a GPG signature, which PyPI no longer
			// accepts either, are ignored.
			io.Copy(io.Discard, p)
		default:
			b, err := io.ReadAll(io.LimitReader(p, maxFormField+1))
			if err != nil {
				return fail(errorf(http.StatusBadRequest, "invalid upload form: %v", err))
			}
			if len(b) > maxFormField {
				return fail(errorf(http.StatusRequestEntityTooLarge, "the upload form field %s is too large", abbrev(name)))
			}
			if total += len(b); total > maxForm {
				return fail(errorf(http.StatusRequestEntityTooLarge, "the upload form is too large"))
			}
			u.form[name] = append(u.form[name], string(b))
		}
	}
	if u.up == nil {
		return nil, errorf(http.StatusBadRequest, "the upload has no file: send it in the form field \"content\"")
	}
	return u, nil
}

// checkedUpload is an upload whose form passed validation.
type checkedUpload struct {
	project string // normalized
	name    string // as given
	version string
	dist    distInfo
	sha256  blob.Digest // as the client sent it, or zero
	md5     []byte
	blake   []byte
}

// check validates the upload form against the file, as PyPI does.
func (u *upload) check() (*checkedUpload, error) {
	bad := func(format string, args ...any) (*checkedUpload, error) {
		return nil, errorf(http.StatusBadRequest, format, args...)
	}
	switch a := first(u.form, ":action"); a {
	case "file_upload":
	case "":
		return bad("the upload form has no :action; send file_upload")
	default:
		return bad("unsupported :action %q; only file_upload is supported", abbrev(a))
	}
	if v := first(u.form, "protocol_version"); v != "" && v != "1" {
		return bad("unsupported protocol_version %q", abbrev(v))
	}
	if len(u.form["attestations"]) > 0 {
		return bad("attestations (PEP 740) are not supported; upload without them")
	}
	c := &checkedUpload{name: first(u.form, "name"), version: first(u.form, "version")}
	if !ValidProjectName(c.name) {
		return bad("invalid project name %q: use letters, digits, \".\", \"_\", and \"-\", starting and ending with a letter or digit", abbrev(c.name))
	}
	c.project = Normalize(c.name)
	if _, ok := parseVersion(c.version); !ok {
		return bad("invalid version %q: it must follow PEP 440", abbrev(c.version))
	}
	if !validFilename(u.filename) {
		return bad("invalid file name %q", abbrev(u.filename))
	}
	filetype := first(u.form, "filetype")
	switch {
	case strings.HasSuffix(u.filename, ".whl"):
		if filetype != typeWheel {
			return bad("%s is a wheel, so filetype must be %s, not %q", u.filename, typeWheel, abbrev(filetype))
		}
	case strings.HasSuffix(u.filename, ".tar.gz"), strings.HasSuffix(u.filename, ".zip"):
		if filetype != typeSdist {
			return bad("%s is a source distribution, so filetype must be %s, not %q", u.filename, typeSdist, abbrev(filetype))
		}
	default:
		return bad("unsupported file %s: upload wheels (.whl) and source distributions (.tar.gz or .zip)", u.filename)
	}
	dist, ok := parseFilename(u.filename, c.project)
	switch {
	case !ok && dist.PackageType == typeWheel:
		return bad("the wheel name %s does not follow {name}-{version}(-{build})?-{python}-{abi}-{platform}.whl for project %s", u.filename, c.name)
	case !ok:
		return bad("the file name %s does not start with the project name %s and a version", u.filename, c.name)
	case canonicalVersion(dist.Version) != canonicalVersion(c.version):
		return bad("the file name %s has version %s, but the upload is version %s", u.filename, dist.Version, c.version)
	}
	c.dist = dist
	for _, d := range []struct {
		field string
		size  int
		out   *[]byte
	}{{"sha256_digest", 32, nil}, {"md5_digest", 16, &c.md5}, {"blake2_256_digest", 32, &c.blake}} {
		s := strings.ToLower(strings.TrimSpace(first(u.form, d.field)))
		if s == "" {
			continue
		}
		b, err := hex.DecodeString(s)
		if err != nil || len(b) != d.size {
			return bad("%s %q is not %d hex digits", d.field, abbrev(s), 2*d.size)
		}
		if d.out != nil {
			*d.out = b
		} else {
			c.sha256, _ = blob.ParseDigest("sha256:" + s)
		}
	}
	return c, nil
}

// storeUpload validates an upload, commits its file and metadata to the
// blob store, and records the file. It reports false if the same file was
// already uploaded, which is not an error.
func (h *Handler) storeUpload(r *http.Request, rp *repository, u *upload) (bool, error) {
	ctx := r.Context()
	c, err := u.check()
	if err != nil {
		return false, err
	}
	fk := fileKey(rp.name, u.filename)
	// A tombstone refuses the name before the file is committed.
	v := h.view()
	if rec, ok := v.Get(fk); ok {
		if f, err := decodeFile(rec.Value); err == nil && f.Kind == kindTombstone {
			v.Release()
			return false, reusedName(u.filename)
		}
	}
	v.Release()
	md5sum, blakesum := u.md5.Sum(nil), u.blake.Sum(nil)
	if c.md5 != nil && !bytes.Equal(c.md5, md5sum) {
		return false, errorf(http.StatusBadRequest, "the file does not match md5_digest: its MD5 is %x", md5sum)
	}
	if c.blake != nil && !bytes.Equal(c.blake, blakesum) {
		return false, errorf(http.StatusBadRequest, "the file does not match blake2_256_digest: its BLAKE2b-256 is %x", blakesum)
	}
	info, err := u.up.Commit(ctx, c.sha256)
	if errors.Is(err, blob.ErrDigestMismatch) {
		return false, errorf(http.StatusBadRequest, "the file does not match sha256_digest: %v", err)
	}
	if err != nil {
		return false, err
	}
	rec := &fileRecord{
		Kind: kindHosted, Project: c.project, Version: c.version, Digest: info.Digest, Size: info.Size,
		MD5: md5sum, Blake2b: blakesum, Uploaded: h.now().UTC(),
		RequiresPython: strings.TrimSpace(first(u.form, "requires_python")),
		PackageType:    c.dist.PackageType, PythonVersion: c.dist.PythonVersion,
	}
	if done, err := h.existingUpload(fk, rec); done || err != nil {
		return false, err
	}
	if err := h.storeMetadata(ctx, u, c, rec); err != nil {
		return false, err
	}
	digests := []blob.Digest{rec.Digest, rec.Meta}
	for attempt := 0; ; attempt++ {
		v := h.view()
		var b meta.Batch
		err := gc.Guard(v, &b, digests...)
		if err == nil {
			b.Require(fk, 0)
			pk := projectKey(rp.name, c.project)
			if _, ok := v.Get(pk); !ok {
				b.Require(pk, 0)
				b.Put(pk, (&projectRecord{Name: c.name, Created: rec.Uploaded}).encode())
			}
			b.Put(fk, rec.encode())
			b.Put(indexKey(rp.name, c.project, u.filename), newEnc())
			b.SetOrigin(h.origin(r, "pypi.upload", rp.name+"/"+c.project+"/"+u.filename))
		}
		v.Release()
		if err == nil {
			err = h.statBlobs(ctx, digests...)
		}
		if err == nil {
			_, err = h.meta.Commit(ctx, &b)
		}
		switch {
		case err == nil:
			h.uploads.With(rp.name).Inc()
			h.uploadBytes.With(rp.name).Add(float64(rec.Size))
			h.log.InfoContext(ctx, "pypi file uploaded", "repository", rp.name, "project", c.project,
				"file", u.filename, "digest", rec.Digest.String(), "size", rec.Size)
			return true, nil
		case errors.Is(err, meta.ErrConflict) && attempt < maxLinkAttempts-1:
			// Another upload of the name, or a garbage-collection sweep,
			// got there first.
			if done, err := h.existingUpload(fk, rec); done || err != nil {
				return false, err
			}
		case errors.Is(err, meta.ErrConflict), errors.Is(err, gc.ErrDoomed):
			return false, errRetry
		default:
			return false, err
		}
	}
}

// maxLinkAttempts bounds how often a batch is retried after a metadata
// precondition fails.
const maxLinkAttempts = 4

// errRetry means a batch lost a race with garbage collection or another
// writer and the client should retry.
var errRetry = errorf(http.StatusServiceUnavailable, "the registry is busy with this content; retry the request")

func reusedName(filename string) error {
	return errorf(http.StatusConflict, "File already exists: %s was deleted, and a file name can never be used again; upload a new version", filename)
}

// existingUpload checks the upload of rec against a file already recorded
// under its name: the same content is done, different content is
// refused, and none lets the upload proceed.
func (h *Handler) existingUpload(fk []byte, rec *fileRecord) (bool, error) {
	v := h.view()
	defer v.Release()
	cur, ok := v.Get(fk)
	if !ok {
		return false, nil
	}
	f, err := decodeFile(cur.Value)
	if err != nil {
		return true, err
	}
	switch {
	case f.Kind == kindTombstone:
		return true, reusedName(string(fk[bytes.LastIndexByte(fk, 0)+1:]))
	case f.Digest == rec.Digest:
		return true, nil
	}
	return true, errorf(http.StatusConflict, "File already exists: %s was uploaded with different content, and a file name can never be reused; upload a new version",
		string(fk[bytes.LastIndexByte(fk, 0)+1:]))
}

// statBlobs checks that blobs exist, after the view that guarded the
// batch was read.
func (h *Handler) statBlobs(ctx context.Context, ds ...blob.Digest) error {
	for _, d := range ds {
		if d.IsZero() {
			continue
		}
		if _, err := h.blobs.Stat(ctx, d); errors.Is(err, blob.ErrNotFound) {
			return errRetry // swept since it was committed; the client uploads again
		} else if err != nil {
			return err
		}
	}
	return nil
}

// storeMetadata extracts the file's core metadata and commits it to the
// blob store, filling in rec's Meta fields. A wheel without valid
// metadata is refused. For a file without metadata flint can read, the
// metadata comes from the upload form, and is used by the JSON API but
// not served as the file's core-metadata file.
func (h *Handler) storeMetadata(ctx context.Context, u *upload, c *checkedUpload, rec *fileRecord) error {
	var md []byte
	f, err := h.blobs.Open(ctx, rec.Digest)
	if err != nil {
		return err
	}
	ra, _ := f.(io.ReaderAt)
	switch {
	case c.dist.PackageType == typeWheel && ra == nil:
		err = errors.New("pypi: the blob store cannot read files at offsets")
	case c.dist.PackageType == typeWheel:
		if md, err = wheelMetadata(ra, rec.Size, c.project, c.version); err != nil {
			err = errorf(http.StatusBadRequest, "invalid wheel %s: %v", u.filename, err)
		}
	default:
		if b, err := sdistMetadata(f, ra, rec.Size, u.filename, c.project, c.version); err == nil {
			md = b
			rec.MetaServed = reliableSdistMetadata(parseMetadata(b))
		}
	}
	f.Close()
	if err != nil {
		return err
	}
	if md == nil {
		md = formMetadata(u.form)
	} else if c.dist.PackageType == typeWheel {
		rec.MetaServed = true
	}
	if rp := parseMetadata(md).get("requires-python"); rp != "" {
		rec.RequiresPython = rp
	}
	info, err := h.putBlob(ctx, md)
	if err != nil {
		return err
	}
	rec.Meta, rec.MetaSize = info.Digest, info.Size
	return nil
}

// putBlob commits b to the blob store.
func (h *Handler) putBlob(ctx context.Context, b []byte) (blob.Info, error) {
	up, err := h.blobs.NewUpload(ctx)
	if err != nil {
		return blob.Info{}, err
	}
	if _, err := up.Write(b); err != nil {
		up.Cancel()
		return blob.Info{}, err
	}
	return up.Commit(ctx, blob.FromBytes(b))
}
