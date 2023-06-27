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
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/pgzip"

	"gitlab.alpinelinux.org/alpine/go/pkg/repository"
	"go.opentelemetry.io/otel"
)

func (a *APK) Combine(ctx context.Context, w io.Writer, sourceDateEpoch *time.Time) error {
	ctx, span := otel.Tracer("go-apk").Start(ctx, "Combine")
	defer span.End()

	start := time.Now()
	defer func() {
		a.logger.Printf("Combine() took %s", time.Since(start))
	}()

	allpkgs, conflicts, err := a.ResolveWorld(ctx)
	if err != nil {
		return fmt.Errorf("error getting package dependencies: %w", err)
	}
	if len(conflicts) != 0 {
		return fmt.Errorf("conflicts: %v", conflicts)
	}

	for _, pkg := range allpkgs {
		a.logger.Printf("appending %s", pkg.Filename())
		// TODO(jonjohnsonjr): If we need to check this, we should make it not slow.

		// isInstalled, err := a.isInstalledPackage(pkg.Name)
		// if err != nil {
		// 	return fmt.Errorf("error checking if package %s is installed: %w", pkg.Name, err)
		// }
		// if isInstalled {
		// 	continue
		// }
		// get the apk file
		if err := a.appendPackage(ctx, w, pkg, sourceDateEpoch); err != nil {
			return err
		}
	}

	if err := a.appendMetadata(ctx, w, sourceDateEpoch); err != nil {
		return err
	}

	// TODO: The rest of the owl.

	// if err := di.MutateAccounts(fsys, o, ic); err != nil {
	// 	return fmt.Errorf("failed to mutate accounts: %w", err)
	// }

	// if err := di.MutatePaths(fsys, o, ic); err != nil {
	// 	return fmt.Errorf("failed to mutate paths: %w", err)
	// }

	// if err := di.GenerateOSRelease(fsys, o, ic); err != nil {
	// 	if errors.Is(err, ErrOSReleaseAlreadyPresent) {
	// 		o.Logger().Warnf("did not generate /etc/os-release: %v", err)
	// 	} else {
	// 		return fmt.Errorf("failed to generate /etc/os-release: %w", err)
	// 	}
	// }

	// if err := di.WriteSupervisionTree(s6context, ic); err != nil {
	// 	return fmt.Errorf("failed to write supervision tree: %w", err)
	// }

	// // add busybox symlinks
	// if err := di.InstallBusyboxLinks(fsys, o); err != nil {
	// 	return err
	// }

	// // add ldconfig links
	// if err := di.InstallLdconfigLinks(fsys); err != nil {
	// 	return err
	// }

	// // add necessary character devices
	// if err := di.InstallCharDevices(fsys); err != nil {
	// 	return err
	// }

	return nil
}

func (a *APK) appendPackage(ctx context.Context, w io.Writer, pkg *repository.RepositoryPackage, sourceDateEpoch *time.Time) error {
	ctx, span := otel.Tracer("go-apk").Start(ctx, "appendPackage")
	defer span.End()

	a.logger.Debugf("installing %s (%s)", pkg.Name, pkg.Version)

	r, err := a.fetchPackage(ctx, pkg)
	if err != nil {
		return err
	}
	defer r.Close()

	split, err := a.splitApk(ctx, pkg)
	if err != nil {
		return fmt.Errorf("splitApk: %w", err)
	}

	installedFiles := split.Files

	compressed, err := split.Compressed()
	if err != nil {
		return err
	}
	defer compressed.Close()

	if err := a.appendAPK(ctx, w, compressed); err != nil {
		return fmt.Errorf("appendApk %q: %w", pkg.Name, err)
	}

	a.logger.Printf("installed files: %d", len(installedFiles))

	// update the scripts.tar
	controlData := bytes.NewReader(split.Control)

	if err := a.updateScriptsTar(pkg.Package, controlData, sourceDateEpoch); err != nil {
		return fmt.Errorf("unable to update scripts.tar for pkg %s: %w", pkg.Name, err)
	}

	// update the triggers
	if _, err := controlData.Seek(0, 0); err != nil {
		return fmt.Errorf("unable to seek to start of control data for pkg %s: %w", pkg.Name, err)
	}
	if err := a.updateTriggers(pkg.Package, controlData); err != nil {
		return fmt.Errorf("unable to update triggers for pkg %s: %w", pkg.Name, err)
	}

	// update the installed file
	if err := a.addInstalledPackage(pkg.Package, installedFiles); err != nil {
		return fmt.Errorf("unable to update installed file for pkg %s: %w", pkg.Name, err)
	}
	return nil
}

func (a *APK) appendMetadata(ctx context.Context, w io.Writer, sourceDateEpoch *time.Time) error {
	ctx, span := otel.Tracer("go-apk").Start(ctx, "appendMetadata")
	defer span.End()

	for _, fn := range []string{
		scriptsFilePath,
		triggersFilePath,
		installedFilePath,
	} {
		f, err := a.fs.OpenFile(fn, os.O_RDONLY, 0)
		if err != nil {
			return fmt.Errorf("unable to open %q: %w", fn, err)
		}
		defer f.Close()
	}

	return nil
}

type splitApk struct {
	// Whether or not the apk contains a signature
	// Note: currently unused
	Signed bool

	// The package signature (a.k.a. ".SIGN...") in tar.gz format
	Signature []byte

	// the control data (a.k.a. ".PKGINFO") in tar.gz format
	Control []byte

	Files []tar.Header

	// filenames for compressed and uncompressed data sections
	compressed   string
	uncompressed string
}

func (s *splitApk) Compressed() (io.ReadCloser, error) {
	return os.Open(s.compressed)
}

func (s *splitApk) Uncompressed() (io.ReadCloser, error) {
	return os.Open(s.uncompressed)
}

// forked from ExpandApk
func (a *APK) splitApk(ctx context.Context, pkg *repository.RepositoryPackage) (*splitApk, error) {
	ctx, span := otel.Tracer("go-apk").Start(ctx, "splitApk")
	defer span.End()

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
	tr := io.TeeReader(exR, sw)
	gzi, err := gzip.NewReader(tr)
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
		if err := gzi.Reset(tr); err != nil {
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

	controlData, err := os.ReadFile(gzipStreams[controlDataIndex])
	if err != nil {
		return nil, fmt.Errorf("unable to read control data: %w", err)
	}

	split := splitApk{
		Signed:  signed,
		Control: controlData,
	}
	if signed {
		b, err := os.ReadFile(gzipStreams[0])
		if err != nil {
			return nil, fmt.Errorf("could not read signature file %s: %w", gzipStreams[0], err)
		}
		split.Signature = b
	}

	// TODO(jonjohnsonjr): Do this during the first decompression.
	dataFile := gzipStreams[controlDataIndex+1]
	r, err := os.Open(dataFile)
	if err != nil {
		return nil, fmt.Errorf("open %q: %w", dataFile, err)
	}
	defer r.Close()

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

	split.uncompressed = p + ".tar"
	split.compressed = p + ".targz"

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

	split.Files, err = a.truncateEOF(ctx, ztrunc, trunc, r)
	if err != nil {
		return nil, fmt.Errorf("truncating %q: %w", dataFile, err)
	}

	return &split, nil
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
