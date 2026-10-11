package cargo

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/gc"
	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/repo"
)

// hostedCrate returns the record of a hosted crate, by any spelling of
// its name, or nil.
func hostedCrate(v meta.View, rp *repository, name string) (*crateRecord, meta.Record, error) {
	rec, ok := v.Get(crateKey(rp.name, Normalize(name)))
	if !ok {
		return nil, rec, nil
	}
	c, err := decodeCrate(rec.Value)
	if err != nil {
		return nil, rec, fmt.Errorf("cargo: crate record of %s in %s: %w", name, rp.name, err)
	}
	return c, rec, nil
}

// hostedIndex returns the lines of a hosted crate's index file, for its
// lowercase name, and the file's ETag, which the crate record's version
// gives, since every change to the crate rewrites the record. Only the
// spelling the crate was first published with has an index file; a crate
// without published versions has none.
func hostedIndex(v meta.View, rp *repository, crate string) ([]*entry, string, error) {
	c, crec, err := hostedCrate(v, rp, crate)
	if err != nil {
		return nil, "", err
	}
	if c == nil || strings.ToLower(c.Name) != crate {
		return nil, "", notFound(crate)
	}
	var es []*entry
	pfx := versionsPrefix(rp.name, Normalize(crate))
	v.Scan(pfx, nil, func(k []byte, rec meta.Record) bool {
		vr, derr := decodeVersion(rec.Value)
		if derr != nil {
			err = fmt.Errorf("cargo: metadata key %q: %w", k, derr)
			return false
		}
		if vr.Kind == kindLive {
			es = append(es, &entry{raw: vr.Line, name: c.Name, vers: vr.Vers, key: canonicalVersion(vr.Vers),
				cksum: vr.Digest.Hex(), src: rp.name, rec: vr})
		}
		return true
	})
	if err != nil {
		return nil, "", err
	}
	if len(es) == 0 {
		return nil, "", notFound(crate)
	}
	return es, fmt.Sprintf(`"%s-%d"`, rp.name, crec.Version), nil
}

func notFound(crate string) error {
	return errorf(http.StatusNotFound, "crate %s is not found", crate)
}

// hostedVersion returns the record of a live version of a hosted crate.
func hostedVersion(v meta.View, rp *repository, crate, vers string) (*versionRecord, error) {
	rec, ok := v.Get(versionKey(rp.name, Normalize(crate), canonicalVersion(vers)))
	if !ok {
		return nil, errorf(http.StatusNotFound, "crate %s has no version %s", crate, vers)
	}
	vr, err := decodeVersion(rec.Value)
	if err != nil {
		return nil, err
	}
	if vr.Kind != kindLive {
		return nil, errorf(http.StatusNotFound, "crate %s has no version %s", crate, vers)
	}
	return vr, nil
}

// owns reports whether hosted repository name owns a crate, by its
// normalized name: a version of it was ever published there.
func owns(v meta.View, name, norm string) bool {
	_, ok := v.Get(crateKey(name, norm))
	return ok
}

// Publish limits.
const (
	// maxMetaJSON bounds a publish request's JSON, which holds the README.
	maxMetaJSON = 16 << 20
	// maxCrateSize bounds a .crate file.
	maxCrateSize = 128 << 20
	// maxUnpacked bounds a .crate file's content when it is unpacked to
	// be checked, as crates.io bounds it.
	maxUnpacked = 1 << 30
)

// publishWarnings is the response to a publish.
type publishWarnings struct {
	Warnings struct {
		InvalidCategories []string `json:"invalid_categories"`
		InvalidBadges     []string `json:"invalid_badges"`
		Other             []string `json:"other"`
	} `json:"warnings"`
}

// servePublish serves PUT /cargo/<repo>/api/v1/crates/new: the JSON
// metadata and the .crate file, each after its length as a 32-bit
// little-endian integer.
//
// A publish to a virtual repository with publishTo goes to that hosted
// member, and needs the permissions a publish to it directly needs; it is
// refused if the member's filters do not admit the crate.
func (h *Handler) servePublish(w http.ResponseWriter, r *http.Request, rp *repository) {
	var via *repo.Virtual
	if rp.typ == config.TypeVirtual {
		via = rp.virtual
	}
	target := h.writable(w, r, rp, ActionPull, ActionPush)
	if target == nil {
		return
	}
	if err := h.publish(r, target, via); err != nil {
		h.fail(w, r, err)
		return
	}
	res := publishWarnings{}
	res.Warnings.InvalidCategories, res.Warnings.InvalidBadges, res.Warnings.Other = []string{}, []string{}, []string{}
	writeJSON(w, http.StatusOK, res)
}

// bodyReader reads a request body and remembers why a read failed, so a
// failure to read the body is told apart from invalid content.
type bodyReader struct {
	r   io.Reader
	n   int64
	err error
}

func (b *bodyReader) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	b.n += int64(n)
	if err != nil && err != io.EOF && b.err == nil {
		b.err = err
	}
	return n, err
}

// uploadWriter writes to an upload and remembers why a write failed, so a
// failure to store the .crate file is told apart from invalid content.
type uploadWriter struct {
	w   io.Writer
	err error
}

func (u *uploadWriter) Write(p []byte) (int, error) {
	n, err := u.w.Write(p)
	if err != nil && u.err == nil {
		u.err = err
	}
	return n, err
}

// readLength reads a 32-bit little-endian length.
func readLength(r io.Reader, what string) (int64, error) {
	var b [4]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, errorf(http.StatusBadRequest, "the publish request ends before the length of the %s", what)
	}
	return int64(binary.LittleEndian.Uint32(b[:])), nil
}

// publish reads a publish request and publishes the version to hosted
// repository rp. via is the virtual repository it was sent to, or nil.
func (h *Handler) publish(r *http.Request, rp *repository, via *repo.Virtual) error {
	ctx := r.Context()
	body := &bodyReader{r: r.Body}
	n, err := readLength(body, "metadata")
	if err != nil {
		return err
	}
	if n > maxMetaJSON {
		return errorf(http.StatusRequestEntityTooLarge, "the publish metadata is larger than %d bytes", maxMetaJSON)
	}
	mb := make([]byte, n)
	if _, err := io.ReadFull(body, mb); err != nil {
		return errorf(http.StatusBadRequest, "the publish request ends inside its metadata")
	}
	var m publishMeta
	if err := json.Unmarshal(mb, &m); err != nil {
		return errorf(http.StatusBadRequest, "invalid publish metadata: %v", err)
	}
	if err := m.check(); err != nil {
		return errorf(http.StatusBadRequest, "%v", err)
	}
	if via != nil {
		if err := via.CheckPublish(m.Name); err != nil {
			return errorf(http.StatusForbidden, "%v", err)
		}
	}
	// A name or version that is taken refuses the publish before the
	// .crate file is read.
	if err := h.checkPublish(rp, &m); err != nil {
		return err
	}
	size, err := readLength(body, ".crate file")
	if err != nil {
		return err
	}
	if size > maxCrateSize {
		return errorf(http.StatusRequestEntityTooLarge, "the .crate file is larger than %d bytes", maxCrateSize)
	}
	up, err := h.blobs.NewUpload(ctx)
	if err != nil {
		return err
	}
	defer up.Cancel() // a no-op once committed
	start := body.n
	uw := &uploadWriter{w: up}
	crate := io.TeeReader(io.LimitReader(body, size), uw)
	cerr := checkCrate(crate, m.Name+"-"+m.Vers+"/")
	if _, err := io.Copy(io.Discard, crate); err != nil && cerr == nil {
		cerr = err
	}
	switch {
	case body.err != nil:
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errorf(http.StatusBadRequest, "reading the .crate file: %v", body.err)
	case uw.err != nil:
		return fmt.Errorf("storing the .crate file: %w", uw.err)
	case body.n-start != size:
		return errorf(http.StatusBadRequest, "the publish request ends inside its .crate file")
	case cerr != nil:
		return errorf(http.StatusBadRequest, "invalid .crate file: %v", cerr)
	}
	if k, _ := body.Read(make([]byte, 1)); k != 0 {
		return errorf(http.StatusBadRequest, "the publish request has data after its .crate file")
	}
	info, err := up.Commit(ctx, blob.Digest{})
	if err != nil {
		return err
	}
	now := h.now().UTC()
	line := m.line(info.Digest.Hex(), now)
	rec := &versionRecord{Kind: kindLive, Vers: m.Vers, Line: line.encode(), Digest: info.Digest, Size: info.Size, Published: now}
	if m.Description != nil {
		rec.Description = *m.Description
	}
	norm := Normalize(m.Name)
	ck, vk := crateKey(rp.name, norm), versionKey(rp.name, norm, canonicalVersion(m.Vers))
	for attempt := 0; ; attempt++ {
		v := h.meta.View()
		var b meta.Batch
		err := checkPublishIn(v, rp, &m)
		if err == nil {
			err = gc.Guard(v, &b, info.Digest)
		}
		if err == nil {
			if crec, ok := v.Get(ck); ok {
				// Rewritten, so the index file's ETag moves.
				b.Require(ck, crec.Version)
				b.Put(ck, crec.Value)
			} else {
				b.Require(ck, 0)
				b.Put(ck, (&crateRecord{Name: m.Name, Created: now}).encode())
			}
			b.Require(vk, 0)
			b.Put(vk, rec.encode())
			b.SetOrigin(h.origin(r, "cargo.publish", rp.name+"/"+m.Name+"@"+m.Vers))
		}
		v.Release()
		if err == nil {
			if _, serr := h.blobs.Stat(ctx, info.Digest); errors.Is(serr, blob.ErrNotFound) {
				err = errRetry // swept since it was committed; the client publishes again
			} else if serr != nil {
				err = serr
			}
		}
		if err == nil {
			_, err = h.meta.Commit(ctx, &b)
		}
		switch {
		case err == nil:
			h.publishes.With(rp.name).Inc()
			h.publishBytes.With(rp.name).Add(float64(info.Size))
			h.log.InfoContext(ctx, "crate published", "repository", rp.name, "crate", m.Name, "version", m.Vers,
				"digest", info.Digest.String(), "size", info.Size)
			return nil
		case errors.Is(err, meta.ErrConflict) && attempt < maxLinkAttempts-1:
			// Another publish, or a garbage-collection sweep, got there
			// first: check the name and version again.
		case errors.Is(err, meta.ErrConflict), errors.Is(err, gc.ErrDoomed):
			return errRetry
		default:
			return err
		}
	}
}

// checkPublish checks a publish against what rp holds now; see
// checkPublishIn.
func (h *Handler) checkPublish(rp *repository, m *publishMeta) error {
	v := h.meta.View()
	defer v.Release()
	return checkPublishIn(v, rp, m)
}

// checkPublishIn checks a publish against what rp holds in v: the crate
// must keep the spelling it was first published with, and the version
// must never have been published, not even if it was deleted since, nor
// one differing from it only in build metadata.
func checkPublishIn(v meta.View, rp *repository, m *publishMeta) error {
	c, _, err := hostedCrate(v, rp, m.Name)
	switch {
	case err != nil:
		return err
	case c != nil && c.Name != m.Name:
		return errorf(http.StatusConflict, "crate %s was published as %s, and a crate name that differs only in case or in \"-\" and \"_\" is the same crate; publish it as %s",
			m.Name, c.Name, c.Name)
	}
	rec, ok := v.Get(versionKey(rp.name, Normalize(m.Name), canonicalVersion(m.Vers)))
	if !ok {
		return nil
	}
	vr, err := decodeVersion(rec.Value)
	switch {
	case err != nil:
		return err
	case vr.Kind == kindTombstone:
		return errorf(http.StatusConflict, "crate version %s@%s was deleted, and a version can never be published again; publish a new version",
			m.Name, vr.Vers)
	}
	return errorf(http.StatusConflict, "crate version %s@%s is already published, and a version can never be published again; publish a new version",
		m.Name, vr.Vers)
}

// checkCrate reads a .crate file: a gzip-compressed tar archive whose
// entries are all under prefix, "<name>-<version>/", and which has
// prefix + "Cargo.toml".
func checkCrate(r io.Reader, prefix string) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return errors.New("it is not gzip-compressed")
	}
	unpacked := &io.LimitedReader{R: gz, N: maxUnpacked + 1}
	tr := tar.NewReader(unpacked)
	manifest := false
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if unpacked.N <= 0 {
			return fmt.Errorf("its content is larger than %d bytes", maxUnpacked)
		}
		if err != nil {
			return fmt.Errorf("it is not a tar archive: %v", err)
		}
		switch {
		case hdr.Typeflag == tar.TypeXGlobalHeader:
		case !strings.HasPrefix(hdr.Name, prefix):
			return fmt.Errorf("%s is not in the directory %s", quote(hdr.Name), prefix)
		case hdr.Name == prefix+"Cargo.toml" && hdr.Typeflag == tar.TypeReg:
			manifest = true
		}
	}
	if !manifest {
		return fmt.Errorf("it has no %sCargo.toml", prefix)
	}
	// Read to the end, so the gzip checksum is checked.
	if _, err := io.Copy(io.Discard, unpacked); err != nil {
		return fmt.Errorf("it is not gzip-compressed: %v", err)
	}
	if unpacked.N <= 0 {
		return fmt.Errorf("its content is larger than %d bytes", maxUnpacked)
	}
	return nil
}

// serveYank serves the web API's yank and unyank of a hosted version,
// which need write and change only the index line's yanked field.
func (h *Handler) serveYank(w http.ResponseWriter, r *http.Request, rp *repository, crate, vers string, yank bool) {
	via := rp.virtual
	target := h.writable(w, r, rp, ActionPull, ActionPush)
	if target == nil {
		return
	}
	if via != nil {
		if err := via.CheckPublish(crate); err != nil {
			writeError(w, http.StatusForbidden, "%v", err)
			return
		}
	}
	action := "cargo.unyank"
	if yank {
		action = "cargo.yank"
	}
	err := h.changeVersion(r.Context(), r, target, crate, vers, action, func(vr *versionRecord) (bool, error) {
		l, err := decodeLine(vr.Line)
		if err != nil {
			return false, fmt.Errorf("cargo: the index line of %s@%s: %w", crate, vers, err)
		}
		if l.Yanked == yank {
			return false, nil
		}
		l.Yanked = yank
		vr.Line = l.encode()
		return true, nil
	})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		OK bool `json:"ok"`
	}{true})
}

// changeVersion applies change to the record of a live version of a
// hosted crate, or replaces it with a tombstone if change is nil, in one
// batch that requires it unchanged and rewrites the crate record, so the
// index file's ETag moves, retrying when another change got there first.
// change reports whether it changed the record.
func (h *Handler) changeVersion(ctx context.Context, r *http.Request, rp *repository, crate, vers, action string,
	change func(*versionRecord) (bool, error)) error {
	norm := Normalize(crate)
	ck, vk := crateKey(rp.name, norm), versionKey(rp.name, norm, canonicalVersion(vers))
	for attempt := 0; ; attempt++ {
		v := h.meta.View()
		var b meta.Batch
		vr, err := hostedVersion(v, rp, crate, vers)
		changed := true
		if err == nil {
			if change == nil {
				vr = &versionRecord{Kind: kindTombstone, Vers: vr.Vers, Deleted: h.now().UTC()}
			} else {
				changed, err = change(vr)
			}
		}
		if err == nil && changed {
			crec, _ := v.Get(ck)
			vrec, _ := v.Get(vk)
			b.Require(ck, crec.Version)
			b.Put(ck, crec.Value)
			b.Require(vk, vrec.Version)
			b.Put(vk, vr.encode())
			b.SetOrigin(h.origin(r, action, rp.name+"/"+crate+"@"+vr.Vers))
		}
		v.Release()
		if err != nil || !changed {
			return err
		}
		_, err = h.meta.Commit(ctx, &b)
		switch {
		case err == nil:
			h.log.InfoContext(ctx, "crate version changed", "action", action, "repository", rp.name, "crate", crate, "version", vers)
			return nil
		case errors.Is(err, meta.ErrConflict) && attempt < maxLinkAttempts-1:
		case errors.Is(err, meta.ErrConflict):
			return errRetry
		default:
			return err
		}
	}
}
