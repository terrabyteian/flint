package maven

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/gc"
	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/repo"
	"github.com/terrabyteian/flint/internal/upstream"
)

// liveFile returns the record of the live file at path in hosted
// repository name, or nil.
func liveFile(v meta.View, name, path string) (*fileRecord, error) {
	rec, ok := v.Get(fileKey(name, path))
	if !ok {
		return nil, nil
	}
	f, err := decodeFile(rec.Value)
	if err != nil || f.Kind != kindLive {
		return nil, err
	}
	return f, nil
}

// fileDigests are a hosted file's digests.
func (f *fileRecord) digests() digests {
	sum, _ := hex.DecodeString(f.Digest.Hex())
	return digests{md5: f.MD5, sha1: f.SHA1, sha256: sum, sha512: f.SHA512}
}

// serveHosted answers a GET or HEAD request of a hosted repository.
func (h *Handler) serveHosted(w http.ResponseWriter, r *http.Request, rp *repository, mp *mpath) {
	switch mp.kind {
	case kindFile:
		v := h.meta.View()
		f, err := liveFile(v, rp.name, mp.path)
		v.Release()
		switch {
		case err != nil:
			h.fail(w, r, err)
		case f == nil:
			writeError(w, http.StatusNotFound, "%s is not found", mp.path)
		default:
			h.serveFile(w, r, f, mp.path)
		}
	case kindMetadata:
		b, err := h.hostedDocument(rp.name, mp.dir)
		switch {
		case err != nil:
			h.fail(w, r, err)
		case b == nil:
			writeError(w, http.StatusNotFound, "%s is not found", mp.path)
		default:
			serveDocument(w, r, b)
		}
	case kindSidecar:
		h.serveHostedChecksum(w, r, rp, mp)
	default:
		writeError(w, http.StatusNotFound, "%s is not found", mp.path)
	}
}

// serveHostedChecksum answers a request for a checksum sidecar of a
// hosted file or metadata file, from flint's own digests.
func (h *Handler) serveHostedChecksum(w http.ResponseWriter, r *http.Request, rp *repository, mp *mpath) {
	switch mp.target.kind {
	case kindFile:
		v := h.meta.View()
		f, err := liveFile(v, rp.name, mp.target.path)
		v.Release()
		switch {
		case err != nil:
			h.fail(w, r, err)
		case f == nil:
			writeError(w, http.StatusNotFound, "%s is not found", mp.path)
		default:
			serveChecksum(w, r, f.digests().get(mp.alg))
		}
	case kindMetadata:
		b, err := h.hostedDocument(rp.name, mp.target.dir)
		switch {
		case err != nil:
			h.fail(w, r, err)
		case b == nil:
			writeError(w, http.StatusNotFound, "%s is not found", mp.path)
		default:
			serveDocumentChecksum(w, r, b, mp.alg)
		}
	default:
		writeError(w, http.StatusNotFound, "%s is not found", mp.path)
	}
}

// serveFile serves a hosted file's bytes, with its checksum headers.
func (h *Handler) serveFile(w http.ResponseWriter, r *http.Request, f *fileRecord, path string) {
	rd, err := h.blobs.Open(r.Context(), f.Digest)
	if err != nil {
		h.fail(w, r, fmt.Errorf("maven: opening %s: %w", path, err))
		return
	}
	defer rd.Close()
	f.digests().setHeaders(w)
	w.Header().Set("Content-Type", contentType(path))
	w.Header().Set("ETag", `"`+f.Digest.String()+`"`)
	// The filesystem store returns the *os.File itself, so on plain
	// HTTP/1.1 ServeContent's copy reaches sendfile. It also answers
	// Range and conditional requests, and HEAD.
	http.ServeContent(w, r, "", f.Uploaded, rd)
}

// hostedDocument generates the maven-metadata.xml of directory dir of
// hosted repository name, or returns nil if there is none.
func (h *Handler) hostedDocument(name string, dir []string) ([]byte, error) {
	v := h.meta.View()
	defer v.Release()
	m, err := hostedMetadata(v, name, dir)
	if err != nil || m == nil {
		return nil, err
	}
	return encodeMetadata(m), nil
}

// hostedMetadata generates the metadata of directory dir of hosted
// repository name: a snapshot version's version-level metadata if dir is
// a snapshot version's directory, and otherwise the artifact-level
// metadata of the artifact dir names, the group-level metadata of the
// group it names, or both in one document. It returns nil if there is
// none.
func hostedMetadata(v meta.View, name string, dir []string) (*metadataXML, error) {
	n := len(dir)
	if n >= 3 && IsSnapshot(dir[n-1]) {
		files, err := snapshotFiles(v, name, strings.Join(dir, "/")+"/")
		if err != nil || len(files) == 0 {
			return nil, err
		}
		return snapshotMetadata(strings.Join(dir[:n-2], "."), dir[n-2], dir[n-1], files), nil
	}
	var m *metadataXML
	if n >= 2 {
		group, artifact := strings.Join(dir[:n-1], "."), dir[n-1]
		vs, err := hostedVersions(v, name, group, artifact)
		if err != nil {
			return nil, err
		}
		if len(vs) > 0 {
			m = artifactMetadata(group, artifact, vs, time.Time{})
		}
	}
	ps, err := hostedPlugins(v, name, strings.Join(dir, "."))
	if err != nil {
		return nil, err
	}
	if len(ps) > 0 {
		if m == nil {
			m = &metadataXML{}
		}
		m.Plugins = pluginsMetadata(ps)
	}
	return m, nil
}

// hostedVersions returns the versions of an artifact that have live files
// in hosted repository name.
func hostedVersions(v meta.View, name, group, artifact string) ([]versionEntry, error) {
	pfx := versionPrefix(name, group, artifact)
	var out []versionEntry
	var failure error
	v.Scan(pfx, nil, func(k []byte, rec meta.Record) bool {
		vr, err := decodeVersion(rec.Value)
		if err != nil {
			failure = fmt.Errorf("maven: metadata key %q: %w", k, err)
			return false
		}
		if vr.Files > 0 {
			out = append(out, versionEntry{Version: string(k[len(pfx):]), Updated: vr.Updated})
		}
		return true
	})
	return out, failure
}

// hostedVersion returns the version record of a version of an artifact in
// hosted repository name, or nil.
func hostedVersion(v meta.View, name, group, artifact, version string) (*versionRecord, error) {
	rec, ok := v.Get(versionKey(name, group, artifact, version))
	if !ok {
		return nil, nil
	}
	return decodeVersion(rec.Value)
}

// owns reports whether hosted repository name owns the artifact called
// groupId:artifactId: a file of it was ever deployed there, even if every
// file has been deleted since.
func owns(v meta.View, name, ga string) bool {
	group, artifact, _ := strings.Cut(ga, ":")
	found := false
	v.Scan(versionPrefix(name, group, artifact), nil, func([]byte, meta.Record) bool {
		found = true
		return false
	})
	return found
}

// hostedPlugins returns the plugins of a group in hosted repository name.
func hostedPlugins(v meta.View, name, group string) ([]plugin, error) {
	pfx := pluginPrefix(name, group)
	var out []plugin
	var failure error
	v.Scan(pfx, nil, func(k []byte, rec meta.Record) bool {
		p, err := decodePlugin(rec.Value)
		if err != nil {
			failure = fmt.Errorf("maven: metadata key %q: %w", k, err)
			return false
		}
		out = append(out, plugin{ArtifactID: string(k[len(pfx):]), Prefix: p.Prefix, Name: p.Name})
		return true
	})
	return out, failure
}

// snapshotFiles returns the live timestamped files directly in directory
// dir, a snapshot version's, of hosted repository name.
func snapshotFiles(v meta.View, name, dir string) ([]snapshotFile, error) {
	pfx := fileKey(name, dir)
	var out []snapshotFile
	var failure error
	v.Scan(pfx, nil, func(k []byte, rec meta.Record) bool {
		rest := string(k[len(pfx):])
		if strings.Contains(rest, "/") {
			return true
		}
		mp, ok := parsePath(dir + rest)
		if !ok || mp.kind != kindFile || mp.c.Timestamp == "" {
			return true
		}
		f, err := decodeFile(rec.Value)
		if err != nil {
			failure = fmt.Errorf("maven: metadata key %q: %w", k, err)
			return false
		}
		if f.Kind == kindLive {
			out = append(out, snapshotFile{c: mp.c, updated: f.Uploaded})
		}
		return true
	})
	return out, failure
}

// maxChecksum bounds an uploaded checksum sidecar.
const maxChecksum = 1 << 10

// servePut serves a deploy. A deploy to a virtual repository with
// publishTo goes to that hosted member, and needs the permissions a
// deploy to it directly needs; it is refused if the member's filters do
// not admit the artifact.
func (h *Handler) servePut(w http.ResponseWriter, r *http.Request, rp *repository, mp *mpath) {
	var via *repo.Virtual
	switch {
	case rp.typ == config.TypeVirtual && rp.virtual.PublishTo == "":
		writeError(w, http.StatusMethodNotAllowed,
			"repository %s is a virtual repository without publishTo; deploy to one of its hosted members: %s",
			rp.name, strings.Join(rp.virtual.Hosted(), ", "))
		return
	case rp.typ == config.TypeVirtual:
		via = rp.virtual
	case rp.typ == config.TypeProxy:
		if h.authorize(w, r, rp, ActionPull) {
			writeError(w, http.StatusMethodNotAllowed,
				"repository %s is a read-only proxy of %s; deploy to a hosted repository instead", rp.name, rp.proxy.base)
		}
		return
	}
	if !h.authorize(w, r, rp, ActionPush) {
		return
	}
	if via != nil {
		rp = h.repos[via.PublishTo]
	}
	var err error
	created := true
	switch mp.kind {
	case kindFile:
		created, err = h.deployFile(r, rp, via, mp)
	case kindMetadata:
		err = h.deployMetadata(r, rp, via, mp)
	case kindSidecar:
		err = h.deployChecksum(r, rp, mp)
	default:
		err = errorf(http.StatusBadRequest, "%s is not a file in the Maven 2 repository layout: "+
			"<group path>/<artifactId>/<version>/<artifactId>-<version>[-<classifier>].<extension>", mp.path)
	}
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if created {
		w.WriteHeader(http.StatusCreated)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// checkPolicy checks a file's version against a hosted repository's
// version policy.
func checkPolicy(rp *repository, c *coords) error {
	snapshot := IsSnapshot(c.Version)
	switch {
	case snapshot && rp.policy == config.VersionPolicyRelease:
		return errorf(http.StatusBadRequest, "repository %s accepts release versions only (maven.versionPolicy %q); "+
			"deploy snapshot %s to a snapshot repository", rp.name, rp.policy, c.Version)
	case !snapshot && rp.policy == config.VersionPolicySnapshot:
		return errorf(http.StatusBadRequest, "repository %s accepts snapshot versions only (maven.versionPolicy %q); "+
			"deploy release %s to a release repository", rp.name, rp.policy, c.Version)
	case c.NonUnique:
		return errorf(http.StatusBadRequest, "%s-%s is a non-unique snapshot file name, which only Maven 2 deployed; "+
			"deploy unique, timestamped snapshot versions", c.Artifact, c.Version)
	}
	return nil
}

// deployFile stores an uploaded artifact file under its immutable name:
// identical content again succeeds without a change, and different
// content, or any content under a deleted name, is refused.
func (h *Handler) deployFile(r *http.Request, rp *repository, via *repo.Virtual, mp *mpath) (bool, error) {
	ctx := r.Context()
	c := mp.c
	if err := checkPolicy(rp, c); err != nil {
		return false, err
	}
	if via != nil {
		if err := via.CheckPublish(c.name()); err != nil {
			return false, errorf(http.StatusForbidden, "%v", err)
		}
	}
	fk := fileKey(rp.name, mp.path)
	// A deleted name refuses the upload before the content is stored.
	v := h.meta.View()
	rec, ok := v.Get(fk)
	v.Release()
	if ok {
		if f, err := decodeFile(rec.Value); err == nil && f.Kind == kindTombstone {
			return false, conflict(repo.ErrTombstoned, mp.path)
		}
	}
	up, err := h.blobs.NewUpload(ctx)
	if err != nil {
		return false, err
	}
	defer up.Cancel() // a no-op once committed
	sums, err := upstream.NewSumWriter(upstream.MD5, upstream.SHA1, upstream.SHA512)
	if err != nil {
		return false, err
	}
	if _, err := io.Copy(io.MultiWriter(up, sums), r.Body); err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return false, errorf(http.StatusBadRequest, "reading the uploaded file: %v", err)
	}
	info, err := up.Commit(ctx, blob.Digest{})
	if err != nil {
		return false, err
	}
	now := h.now().UTC()
	s := sums.Sums()
	f := &fileRecord{Kind: kindLive, Digest: info.Digest, Size: info.Size, MD5: s[upstream.MD5], SHA1: s[upstream.SHA1],
		SHA512: s[upstream.SHA512], Uploaded: now}
	vk := versionKey(rp.name, c.Group, c.Artifact, c.Version)
	changed, err := repo.Publish(ctx, h.meta, fk, info.Digest, readExisting, func(v meta.View, b *meta.Batch) error {
		if err := gc.Guard(v, b, info.Digest); err != nil {
			return err
		}
		// The view was read before this check, as the guard needs.
		if _, err := h.blobs.Stat(ctx, info.Digest); errors.Is(err, blob.ErrNotFound) {
			return errRetry // swept since it was committed; the client deploys again
		} else if err != nil {
			return err
		}
		vr := &versionRecord{Created: now, Snapshot: IsSnapshot(c.Version)}
		if rec, ok := v.Get(vk); ok {
			old, err := decodeVersion(rec.Value)
			if err != nil {
				return err
			}
			vr = old
			b.Require(vk, rec.Version)
		} else {
			b.Require(vk, 0)
		}
		vr.Updated, vr.Files = now, vr.Files+1
		if c.Timestamp != "" && (c.Timestamp > vr.Timestamp || c.Timestamp == vr.Timestamp && c.Build > vr.Build) {
			vr.Timestamp, vr.Build = c.Timestamp, c.Build
		}
		b.Put(vk, vr.encode())
		b.Put(fk, f.encode())
		b.SetOrigin(h.origin(r, "maven.deploy", rp.name+"/"+mp.path))
		return nil
	})
	switch {
	case errors.Is(err, repo.ErrPublished), errors.Is(err, repo.ErrTombstoned):
		return false, conflict(err, mp.path)
	case errors.Is(err, gc.ErrDoomed), errors.Is(err, meta.ErrConflict):
		return false, errRetry
	case err != nil:
		return false, err
	case changed:
		h.deploys.With(rp.name).Inc()
		h.deployBytes.With(rp.name).Add(float64(f.Size))
		h.log.InfoContext(ctx, "maven file deployed", "repository", rp.name, "path", mp.path,
			"digest", f.Digest.String(), "size", f.Size)
	}
	return changed, nil
}

// readExisting reads a file record for repo.Publish.
func readExisting(value []byte) (repo.Existing, error) {
	f, err := decodeFile(value)
	if err != nil {
		return repo.Existing{}, err
	}
	return repo.Existing{Tombstone: f.Kind == kindTombstone, Digest: f.Digest}, nil
}

// conflict is the response to a deploy the immutable-name rule refuses.
func conflict(err error, path string) error {
	if errors.Is(err, repo.ErrTombstoned) {
		return errorf(http.StatusConflict, "%s was deleted, and a deleted file's name can never be used again; deploy a new version", path)
	}
	return errorf(http.StatusConflict, "%s is already deployed with different content, and a deployed file never changes; deploy a new version", path)
}

// deployMetadata accepts an uploaded maven-metadata.xml. flint generates
// the artifact-level and version-level documents itself, so their
// uploads are discarded; the plugin entries of group-level metadata,
// which Maven uploads when it deploys a plugin, are kept.
func (h *Handler) deployMetadata(r *http.Request, rp *repository, via *repo.Virtual, mp *mpath) error {
	b, err := io.ReadAll(io.LimitReader(r.Body, maxMetadata+1))
	switch {
	case err != nil:
		return errorf(http.StatusBadRequest, "reading the uploaded metadata: %v", err)
	case len(b) > maxMetadata:
		return errorf(http.StatusRequestEntityTooLarge, "%s is larger than %d bytes", mp.path, maxMetadata)
	}
	m, err := parseMetadata(b)
	if err != nil {
		return errorf(http.StatusBadRequest, "%s: %v", mp.path, err)
	}
	ps := metadataPlugins(m)
	if len(ps) == 0 {
		return nil
	}
	for _, s := range mp.dir {
		if !validName(s) || strings.Contains(s, ".") {
			return errorf(http.StatusBadRequest, "%s lists plugins, but its directory is not a group's", mp.path)
		}
	}
	group := strings.Join(mp.dir, ".")
	if via != nil {
		for _, p := range ps {
			if err := via.CheckPublish(group + ":" + p.ArtifactID); err != nil {
				return errorf(http.StatusForbidden, "%v", err)
			}
		}
	}
	var batch meta.Batch
	for _, p := range ps {
		batch.Put(pluginKey(rp.name, group, p.ArtifactID), (&pluginRecord{Prefix: p.Prefix, Name: p.Name}).encode())
	}
	batch.SetOrigin(h.origin(r, "maven.deploy", rp.name+"/"+mp.path))
	_, err = h.meta.Commit(r.Context(), &batch)
	return err
}

// deployChecksum accepts an uploaded checksum sidecar: flint serves
// sidecars from its own digests, so the upload is only checked against
// the file it is a checksum of, if that is stored, and discarded.
func (h *Handler) deployChecksum(r *http.Request, rp *repository, mp *mpath) error {
	b, err := io.ReadAll(io.LimitReader(r.Body, maxChecksum+1))
	switch {
	case err != nil:
		return errorf(http.StatusBadRequest, "reading the uploaded checksum: %v", err)
	case len(b) > maxChecksum:
		return errorf(http.StatusBadRequest, "%s is not a checksum: it is larger than %d bytes", mp.path, maxChecksum)
	}
	switch mp.target.kind {
	case kindFile:
	case kindMetadata:
		return nil
	default:
		return errorf(http.StatusBadRequest, "%s is not a checksum of a file in the Maven 2 repository layout", mp.path)
	}
	sum, ok := parseChecksum(b, len(digestsOf(nil).get(mp.alg)))
	if !ok {
		return errorf(http.StatusBadRequest, "%s is not a %s checksum", mp.path, mp.alg)
	}
	v := h.meta.View()
	f, err := liveFile(v, rp.name, mp.target.path)
	v.Release()
	if err != nil || f == nil {
		return err
	}
	if want := f.digests().get(mp.alg); !bytes.Equal(sum, want) {
		return errorf(http.StatusBadRequest, "%s says %x, but the deployed file's %s is %x", mp.path, sum, mp.alg, want)
	}
	return nil
}

// parseChecksum reads a checksum sidecar: a hex digest of size bytes,
// optionally followed by white space and a file name.
func parseChecksum(b []byte, size int) ([]byte, bool) {
	fields := strings.Fields(string(b))
	if len(fields) == 0 {
		return nil, false
	}
	sum, err := hex.DecodeString(strings.ToLower(fields[0]))
	if err != nil || len(sum) != size {
		return nil, false
	}
	return sum, true
}

// serveDelete deletes a hosted file, or every file of a version when the
// path is a version's directory. A deleted file leaves a tombstone, so
// its name is never used again, and garbage collection reclaims its
// bytes. A delete through a virtual repository with publishTo deletes
// from that hosted member.
func (h *Handler) serveDelete(w http.ResponseWriter, r *http.Request, rp *repository, mp *mpath) {
	switch {
	case rp.typ == config.TypeVirtual && rp.virtual.PublishTo == "":
		writeError(w, http.StatusMethodNotAllowed,
			"repository %s is a virtual repository without publishTo; delete from one of its hosted members: %s",
			rp.name, strings.Join(rp.virtual.Hosted(), ", "))
		return
	case rp.typ == config.TypeProxy:
		if h.authorize(w, r, rp, ActionPull) {
			writeError(w, http.StatusMethodNotAllowed, "repository %s is a read-only proxy repository", rp.name)
		}
		return
	}
	if !h.authorize(w, r, rp, ActionDelete) {
		return
	}
	if rp.typ == config.TypeVirtual {
		rp = h.repos[rp.virtual.PublishTo]
	}
	var c *coords
	var dir string
	switch {
	case mp.kind == kindFile:
		c = mp.c
	case mp.kind == kindOther && strings.HasSuffix(mp.path, "/"):
		segs := strings.Split(strings.TrimSuffix(mp.path, "/"), "/")
		if n := len(segs); n >= 3 && validName(segs[n-2]) {
			c = &coords{Group: strings.Join(segs[:n-2], "."), Artifact: segs[n-2], Version: segs[n-1]}
			dir = mp.path
		}
	}
	if c == nil {
		writeError(w, http.StatusBadRequest, "%s is neither an artifact file nor a version's directory", mp.path)
		return
	}
	n, err := h.deleteFiles(r, rp, c, mp.path, dir)
	switch {
	case err != nil:
		h.fail(w, r, err)
	case n == 0:
		writeError(w, http.StatusNotFound, "%s is not found", mp.path)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// deleteFiles turns the live file at path, or with dir every live file
// directly in that version directory, into tombstones, and returns how
// many it deleted.
func (h *Handler) deleteFiles(r *http.Request, rp *repository, c *coords, path, dir string) (int, error) {
	ctx := r.Context()
	now := h.now().UTC()
	for range maxAttempts {
		v := h.meta.View()
		var b meta.Batch
		n, err := h.deleteBatch(v, &b, rp, c, path, dir, now)
		v.Release()
		if err != nil || n == 0 {
			return 0, err
		}
		b.SetOrigin(h.origin(r, "maven.delete", rp.name+"/"+path))
		_, err = h.meta.Commit(ctx, &b)
		switch {
		case err == nil:
			h.log.InfoContext(ctx, "maven files deleted", "repository", rp.name, "path", path, "files", n)
			return n, nil
		case !errors.Is(err, meta.ErrConflict):
			return 0, err
		}
	}
	return 0, errRetry
}

// maxAttempts bounds how often a batch is retried after a metadata
// precondition fails.
const maxAttempts = 4

// deleteBatch adds the deletes of deleteFiles to b, read in view v.
func (h *Handler) deleteBatch(v meta.View, b *meta.Batch, rp *repository, c *coords, path, dir string, now time.Time) (int, error) {
	tomb := (&fileRecord{Kind: kindTombstone, Deleted: now}).encode()
	n := 0
	del := func(k []byte, rec meta.Record) error {
		f, err := decodeFile(rec.Value)
		if err != nil {
			return fmt.Errorf("maven: metadata key %q: %w", k, err)
		}
		if f.Kind != kindLive {
			return nil
		}
		b.Require(k, rec.Version)
		b.Put(k, tomb)
		n++
		return nil
	}
	if dir == "" {
		if rec, ok := v.Get(fileKey(rp.name, path)); ok {
			if err := del(fileKey(rp.name, path), rec); err != nil {
				return 0, err
			}
		}
	} else {
		pfx := fileKey(rp.name, dir)
		var failure error
		v.Scan(pfx, nil, func(k []byte, rec meta.Record) bool {
			if strings.Contains(string(k[len(pfx):]), "/") {
				return true
			}
			failure = del(bytes.Clone(k), rec)
			return failure == nil
		})
		if failure != nil {
			return 0, failure
		}
	}
	if n == 0 {
		return 0, nil
	}
	vk := versionKey(rp.name, c.Group, c.Artifact, c.Version)
	if rec, ok := v.Get(vk); ok {
		vr, err := decodeVersion(rec.Value)
		if err != nil {
			return 0, err
		}
		vr.Files = max(vr.Files-n, 0)
		b.Require(vk, rec.Version)
		b.Put(vk, vr.encode())
	}
	return n, nil
}
