// THIS FILE IS AN EXACT DUPLICATE OF STUFF IN ALPINE-GO!
// Unfortunately, all of that is package-private rather than public,
// so we are duplicating it here. As soon as we can upstream this entire impl,
// this duplicate file goes away!

//nolint:all
package apk

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"go.opentelemetry.io/otel"
)

// The length of a gzip header
const gzipHeaderLength = 10

// APKExpanded contains information about and reference to an expanded APK package.
// Close() deletes all temporary files and directories created during the expansion process.
type APKExpanded struct {
	// The size in bytes of the entire apk (sum of all tar.gz file sizes)
	Size int64

	// Whether or not the apk contains a signature
	// Note: currently unused
	Signed bool

	// The temporary parent directory containing all exploded .tar/.tar.gz contents
	tempDir string

	// The package signature filename (a.k.a. ".SIGN...") in tar.gz format
	SignatureFile string

	// The control data filename (a.k.a. ".PKGINFO") in tar.gz format
	ControlFile string

	// The package data filename in tar.gz format
	PackageFile string
}

func (a *APKExpanded) APK() (io.ReadCloser, error) {
	rs := []io.Reader{}
	cs := []io.Closer{}

	for _, fn := range []string{a.SignatureFile, a.ControlFile, a.PackageFile} {
		if fn != "" {
			f, err := os.Open(fn)
			if err != nil {
				return nil, err
			}
			rs = append(rs, f)
			cs = append(cs, f)
		}
	}

	return &multiReadCloser{
		r:       io.MultiReader(rs...),
		closers: cs,
	}, nil
}

type multiReadCloser struct {
	r       io.Reader
	closers []io.Closer
}

func (m *multiReadCloser) Read(p []byte) (int, error) {
	return m.r.Read(p)
}

func (m *multiReadCloser) Close() error {
	errs := make([]error, len(m.closers))
	for i, closer := range m.closers {
		errs[i] = closer.Close()
	}
	return errors.Join(errs...)
}

func (a *APKExpanded) Close() error {
	if a.tempDir == "" {
		return nil
	}

	return os.RemoveAll(a.tempDir)
}

// An implementation of io.Writer designed specifically for use in the expandApk() method.
// This wraps os.File, and allows the same writer to be used to write across multiple files.
// The Next() method can be called at any point, which increments "streamId" and sets the
// underlying file to a new file with name in the form <parentDir>/<baseName>-<streamId>.<ext>
type expandApkWriter struct {
	parentDir  string
	baseName   string
	ext        string
	streamId   int
	maxStreams int
	f          *os.File
}

func newExpandApkWriter(parentDir string, baseName string, ext string) (*expandApkWriter, error) {
	sw := expandApkWriter{
		parentDir:  parentDir,
		baseName:   baseName,
		ext:        ext,
		streamId:   -1,
		maxStreams: 2,
	}
	if err := sw.Next(); err != nil {
		return nil, fmt.Errorf("newExpandApkWriter: %w", err)
	}
	return &sw, nil
}

func (sw *expandApkWriter) Write(p []byte) (int, error) {
	i, err := sw.f.Write(p)
	if err != nil {
		err = fmt.Errorf("expandApkWriter.Write: %w", err)
	}
	return i, err
}

var _ io.Writer = (*expandApkWriter)(nil)

var errExpandApkWriterMaxStreams = errors.New("expandApkWriter max streams reached")

func (w *expandApkWriter) Next() error {
	if w.f != nil {
		if err := w.CloseFile(); err != nil {
			return fmt.Errorf("expandApkWriter.Next error 1: %v", err)
		}
	}

	// When the first stream is done writing, open up the tarball and
	// determine if it is a signature. If so, bump the max streams from 2 to 3.
	// The final stream should contain the entirety of the actual package contents
	if w.streamId == 0 {
		f, err := os.Open(w.f.Name())
		if err != nil {
			return fmt.Errorf("expandApkWriter.Next error 2: %v", err)
		}
		defer f.Close()
		gzipRead, err := gzip.NewReader(f)
		if err != nil {
			return fmt.Errorf("expandApkWriter.Next error 3: %v", err)
		}
		defer gzipRead.Close()
		tarRead := tar.NewReader(gzipRead)
		hdr, err := tarRead.Next()
		if err != nil {
			return fmt.Errorf("expandApkWriter.Next error 4: %v", err)
		}
		if strings.HasPrefix(hdr.Name, ".SIGN.") {
			w.maxStreams = 3
		}
	}

	w.streamId++
	p := fmt.Sprintf("%s-%d.%s", filepath.Join(w.parentDir, w.baseName), w.streamId, w.ext)
	file, err := os.Create(p)
	if err != nil {
		return fmt.Errorf("expandApkWriter.Next error 5: %w", err)
	}
	w.f = file

	// At this point, we should have created the final tar.gz file,
	// so inform the consumer of this method to speed up the read
	// by returning this specific error
	if w.streamId+1 >= w.maxStreams {
		return errExpandApkWriterMaxStreams
	}

	return nil
}

func (w expandApkWriter) CurrentName() string {
	return w.f.Name()
}

func (w expandApkWriter) CloseFile() error {
	return w.f.Close()
}

// An implementation of io.Reader designed specifically for use in the expandApk() method.
// When used in combination with the expandApkWrier (based on os.File) in a io.TeeReader,
// the Go stdlib optimizes the write, causing readahead, even if the actual stream size
// is less than the size of the incoming buffer. To fix this, the Read() method on this
// Reader has been modified to read only a single byte at a time to workaround the issue.
type expandApkReader struct {
	io.Reader
	fast bool
}

func newExpandApkReader(r io.Reader) *expandApkReader {
	return &expandApkReader{
		Reader: r,
		fast:   false,
	}
}

func (r *expandApkReader) Read(b []byte) (int, error) {
	if r.fast {
		return r.Reader.Read(b)
	}
	buf := make([]byte, 1)
	n, err := r.Reader.Read(buf)
	if err != nil && err != io.EOF {
		err = fmt.Errorf("expandApkReader.Read: %w", err)
	} else {
		b[0] = buf[0]
	}
	return n, err
}

func (r *expandApkReader) EnableFastRead() {
	r.fast = true
}

// ExpandAPK given a ready to an apk stream, normally a tar stream with gzip compression,
// expand it into its components.
//
// An apk is split into either 2 or 3 file streams (2 for unsigned packages, 3 for signed).
//
// For more info, see https://wiki.alpinelinux.org/wiki/Apk_spec:
//
//	"APK v2 packages contain two tar segments followed by a tarball each in their
//	own gzip stream (3 streams total). These streams contain the package signature,
//	control data, and package data"
//
// Returns an APKExpanded struct containing references to the file. You *must* call APKExpanded.Close()
// when finished to clean up the various files.
func ExpandApk(ctx context.Context, source io.Reader) (*APKExpanded, error) {
	ctx, span := otel.Tracer("go-apk").Start(ctx, "ExpandApk")
	defer span.End()

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

		// TODO(jonjohnsonjr): Use CopyBuffer to speed this up on macOS.
		// TODO(jonjohnsonjr): Do sha256 hashing of overall stream.
		// TODO(jonjohnsonjr): Do sha1 verification of each file based on tar headers.
		// TODO(jonjohnsonjr): Save tar headers in separate file.
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

	// Calculate the total size of the apk (combo of all streams)
	totalSize := int64(0)
	for _, s := range gzipStreams {
		info, err := os.Stat(s)
		if err != nil {
			return nil, fmt.Errorf("expandApk error 18: %w", err)
		}
		totalSize += info.Size()
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

	expanded := APKExpanded{
		tempDir:     dir,
		Signed:      signed,
		Size:        totalSize,
		ControlFile: gzipStreams[controlDataIndex],
		PackageFile: gzipStreams[controlDataIndex+1],
	}
	if signed {
		expanded.SignatureFile = gzipStreams[0]
	}

	return &expanded, nil
}
