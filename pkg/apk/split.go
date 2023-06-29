// Copyright 2023 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package apk

import (
	"archive/tar"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/pgzip"

	"gitlab.alpinelinux.org/alpine/go/pkg/repository"
	"go.opentelemetry.io/otel"
)

type SplitApk struct {
	signature string
	control   string
	installed string
	scripts   string
	triggers  string

	// filenames for compressed and uncompressed data sections
	compressed   string
	uncompressed string
}

func (s *SplitApk) Compressed() (io.ReadCloser, error) {
	return os.Open(s.compressed)
}

func (s *SplitApk) Uncompressed() (io.ReadCloser, error) {
	return os.Open(s.uncompressed)
}

func (s *SplitApk) Control() (io.ReadSeekCloser, error) {
	return os.Open(s.control)
}

func (s *SplitApk) Installed() (io.ReadSeekCloser, error) {
	return os.Open(s.installed)
}

func (s *SplitApk) Scripts() (io.ReadSeekCloser, error) {
	return os.Open(s.scripts)
}

func (s *SplitApk) Triggers() (io.ReadSeekCloser, error) {
	return os.Open(s.triggers)
}

// forked from ExpandApk
func (a *APK) SplitApk(ctx context.Context, pkg *repository.RepositoryPackage) (*SplitApk, error) {
	ctx, span := otel.Tracer("go-apk").Start(ctx, "SplitApk")
	defer span.End()

	// TODO: Align with cache stuff.
	if a.cache == nil {
		return nil, fmt.Errorf("cache is nil")
	}

	u, err := a.url(pkg.Url())
	if err != nil {
		return nil, err
	}

	p, err := cachePathFromURL(a.cache.dir, u)
	if err != nil {
		return nil, err
	}

	split := SplitApk{
		uncompressed: p + ".tar",
		compressed:   p + ".targz",
		control:      p + ".control",
		signature:    p + ".sig",
		installed:    p + ".installed",
		scripts:      p + ".scripts",
		triggers:     p + ".triggers",
	}

	// TODO(jonjohnsonjr): Better way to check to see if this already exists and skip it.
	if _, err := split.Control(); err == nil {
		return &split, nil
	}

	// Check to see if this stuff exists.

	// TODO(jonjohnsonjr): Do we need to handle APKv1.0 compatibility?
	// per https://git.alpinelinux.org/apk-tools/tree/src/extract_v2.c?id=337734941831dae9a6aa441e38611c43a5fd72c0#n120
	//  * APKv1.0 compatibility - first non-hidden file is
	//  * considered to start the data section of the file.
	//  * This does not make any sense if the file has v2.0
	//  * style .PKGINFO

	source, err := a.fetchPackage(ctx, pkg)
	if err != nil {
		return nil, err
	}
	defer source.Close()

	// TODO(jonjohnsonjr): Base this on cache dir semantics.
	dir, err := os.MkdirTemp("", "")
	if err != nil {
		return nil, err
	}

	sw, err := newExpandApkWriter(dir, "stream", "tar.gz")
	if err != nil {
		return nil, fmt.Errorf("expandApk error 1: %w", err)
	}
	exR := newExpandApkReader(source)
	tee := io.TeeReader(exR, sw)
	gzi, err := gzip.NewReader(tee)
	if err != nil {
		return nil, fmt.Errorf("expandApk error 2: %w", err)
	}
	gzipStreams := []string{}
	maxStreamsReached := false
	for {
		if !maxStreamsReached {
			gzi.Multistream(false)
		}
		_, err := io.Copy(io.Discard, gzi)
		if err != nil {
			return nil, fmt.Errorf("expandApk error 3: %w", err)
		}
		gzipStreams = append(gzipStreams, sw.CurrentName())
		if err := gzi.Reset(tee); err != nil {
			if err == io.EOF {
				break
			} else {
				return nil, fmt.Errorf("expandApk error 4: %w", err)
			}
		}
		if err := sw.Next(); err != nil {
			if err == errExpandApkWriterMaxStreams {
				maxStreamsReached = true
				exR.EnableFastRead()
			} else {
				return nil, fmt.Errorf("expandApk error 5: %w", err)
			}
		}
	}
	if err := gzi.Close(); err != nil {
		return nil, fmt.Errorf("expandApk error 6: %w", err)
	}
	if err := sw.CloseFile(); err != nil {
		return nil, fmt.Errorf("expandApk error 7: %w", err)
	}

	numGzipStreams := len(gzipStreams)

	// Fix streams (magic headers are in wrong stream)
	for i, s := range gzipStreams[:numGzipStreams-1] {
		// 1. take off the last 10 bytes
		f, err := os.Open(s)
		if err != nil {
			return nil, fmt.Errorf("expandApk error 8: %w", err)
		}
		pos, err := f.Seek(-gzipHeaderLength, io.SeekEnd)
		if err != nil {
			return nil, fmt.Errorf("expandApk error 9: %w", err)
		}
		b := make([]byte, gzipHeaderLength)
		if _, err := io.ReadFull(f, b); err != nil {
			return nil, fmt.Errorf("expandApk error 10: %w", err)
		}
		f.Close()
		f, err = os.OpenFile(s, os.O_WRONLY, 0644)
		if err != nil {
			return nil, fmt.Errorf("expandApk error 11: %w", err)
		}
		if err := f.Truncate(pos); err != nil {
			return nil, fmt.Errorf("expandApk error 12: %w", err)
		}

		// 2. prepend them onto the next stream
		nextStream := gzipStreams[i+1]
		f, err = os.Open(nextStream)
		if err != nil {
			return nil, fmt.Errorf("expandApk error 13: %w", err)
		}
		f2, err := os.Create(fmt.Sprintf("%s.tmp", nextStream))
		if err != nil {
			return nil, fmt.Errorf("expandApk error 14: %w", err)
		}
		if _, err := f2.Write(b); err != nil {
			return nil, fmt.Errorf("expandApk error 15: %w", err)
		}
		if _, err := io.Copy(f2, f); err != nil {
			return nil, fmt.Errorf("expandApk error 16: %w", err)
		}
		n := f.Name()
		n2 := f2.Name()
		f.Close()
		f2.Close()
		if err := os.Rename(n2, n); err != nil {
			return nil, fmt.Errorf("expandApk error 17: %w", err)
		}
	}

	var signed bool
	var controlDataIndex int
	switch numGzipStreams {
	case 3:
		signed = true
		controlDataIndex = 1
	case 2:
		controlDataIndex = 0
	default:
		return nil, fmt.Errorf("invalid number of tar streams: %d", numGzipStreams)
	}

	if err := os.Rename(gzipStreams[controlDataIndex], split.control); err != nil {
		return nil, fmt.Errorf("unable to rename control data: %w", err)
	}

	if signed {
		if err := os.Rename(gzipStreams[0], split.signature); err != nil {
			return nil, fmt.Errorf("could not rename signature file %s: %w", gzipStreams[0], err)
		}
	}

	dataFile := gzipStreams[controlDataIndex+1]
	r, err := os.Open(dataFile)
	if err != nil {
		return nil, fmt.Errorf("open %q: %w", dataFile, err)
	}
	defer r.Close()

	trunc, err := os.Create(split.uncompressed)
	if err != nil {
		return nil, err
	}
	defer trunc.Close()

	ztrunc, err := os.Create(split.compressed)
	if err != nil {
		return nil, err
	}
	defer ztrunc.Close()

	installed, err := a.truncateEOF(ctx, ztrunc, trunc, r)
	if err != nil {
		return nil, fmt.Errorf("truncating %q: %w", dataFile, err)
	}

	inst, err := os.Create(split.installed)
	if err != nil {
		return nil, err
	}
	defer inst.Close()

	if err := writeInstalledPackage(inst, pkg.Package, installed); err != nil {
		return nil, fmt.Errorf("unable to write %q for %s: %w", split.installed, pkg.Name, err)
	}

	scripts, err := os.Create(split.scripts)
	if err != nil {
		return nil, err
	}
	defer scripts.Close()

	triggers, err := os.Create(split.triggers)
	if err != nil {
		return nil, err
	}
	defer triggers.Close()

	control, err := split.Control()
	if err != nil {
		return nil, fmt.Errorf("reading control: %w", err)
	}
	defer control.Close()

	zr, err := gzip.NewReader(control)
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(zr)
	tw := tar.NewWriter(scripts)

	// Update scripts and triggers.
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}

		if header.Name == ".PKGINFO" { //nolint:goconst
			if err := writeTriggers(tr, triggers, pkg); err != nil {
				return nil, fmt.Errorf("writing triggers for %s: %w", pkg.Name, err)
			}

			// .PKGINFO is the only file that isn't a script
			continue
		}

		header.Name = fmt.Sprintf("%s-%s.Q1%s%s", pkg.Name, pkg.Version, base64.StdEncoding.EncodeToString(pkg.Checksum), header.Name)
		if err := tw.WriteHeader(header); err != nil {
			return nil, fmt.Errorf("unable to write scripts header for %s: %w", header.Name, err)
		}
		if _, err := io.CopyN(tw, tr, header.Size); err != nil {
			return nil, fmt.Errorf("unable to write content for %s: %w", header.Name, err)
		}
	}

	// Note Flush() not Close() because we don't want to EOF the tar.
	if err := tw.Flush(); err != nil {
		return nil, fmt.Errorf("failed to flush scripts: %w", err)
	}

	return &split, nil
}

func writeTriggers(tr *tar.Reader, w io.Writer, pkg *repository.RepositoryPackage) error {
	b, err := io.ReadAll(tr)
	if err != nil {
		return fmt.Errorf("unable to read .PKGINFO from control tar.gz file: %w", err)
	}
	lines := strings.Split(string(b), "\n")
	for _, line := range lines {
		parts := strings.Split(line, "=")
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if key != "triggers" {
			continue
		}
		if _, err := w.Write([]byte(fmt.Sprintf("%s %s\n", base64.StdEncoding.EncodeToString(pkg.Checksum), value))); err != nil {
			return fmt.Errorf("unable to write triggers file %s: %w", triggersFilePath, err)
		}
		break
	}

	return nil
}

// TODO(jonjohnsonjr): This is serial currently, but we just need a writerAt to fix that.
// TODO(jonjohnsonjr): This may need to handle file conflicts.
// TODO(jonjohnsonjr): We may need to truncate gzipIn prior to tar EOF, but we can do that in melange.
func (a *APK) appendAPK(ctx context.Context, w io.Writer, gzipIn io.Reader) error {
	ctx, span := otel.Tracer("go-apk").Start(ctx, "appendAPK")
	defer span.End()

	// This is a sperate method just for the traces, really.
	_, err := io.Copy(w, gzipIn)
	return err
}

func (a *APK) truncateEOF(ctx context.Context, w io.Writer, uw io.Writer, r io.Reader) ([]tar.Header, error) {
	ctx, span := otel.Tracer("go-apk").Start(ctx, "truncateEOF")
	defer span.End()

	// TODO(jonjohnsonjr): Avoid recompressing every apk by doing clever flate-level things.
	// It is very easy to strip the tar EOF by recompressing everything, but it is very slow.
	// This is still a big win because we can do it once per APK.
	zw := pgzip.NewWriter(w)

	// Before recompressing, also write out the uncompressed tar to uw to avoid paying the flate cost twice.
	mw := io.MultiWriter(zw, uw)

	tw := tar.NewWriter(mw)

	zr, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("gzip.NewReader: %w", err)
	}

	tr := tar.NewReader(zr)

	var files []tar.Header
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("tr.Next(): %w", err)
		}

		files = append(files, *header)

		if err := tw.WriteHeader(header); err != nil {
			return nil, fmt.Errorf("tw.WriteHeader(): %w", err)
		}

		if _, err := io.Copy(tw, tr); err != nil {
			return nil, fmt.Errorf("copying %s: %w", header.Name, err)
		}
	}

	// Note that we are calling Flush, not Close, which would append the EOF marker.
	if err := tw.Flush(); err != nil {
		return nil, fmt.Errorf("flushing tar: %w", err)
	}

	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("closing gzip writer: %w", err)
	}

	return files, nil
}
