package tarball

import (
	"archive/tar"
	"bufio"
	"errors"
	"io"
	"io/fs"
)

type Entry struct {
	tar.Header
	Offset int64
}

type File struct {
	fsys *FS
	io.Reader
	Entry Entry
}

func (f *File) Stat() (fs.FileInfo, error) {
	return f.Entry.FileInfo(), nil
}

func (f *File) ReadAt(p []byte, off int64) (int, error) {
	return -1, fs.ErrInvalid
}

func (f *File) Write(p []byte) (int, error) {
	return -1, fs.ErrInvalid
}

func (f *File) Seek(offset int64, whence int) (int64, error) {
	return -1, fs.ErrInvalid
}

func (f *File) Read(p []byte) (int, error) {
	return f.Reader.Read(p)
}

func (f *File) Close() error {
	return nil
}

// FS will break if you try to read from multiple files at once.
type FS struct {
	r     io.ReadSeekCloser
	files []Entry
	index map[string]int
}

// Open implements fs.FS.
func (fsys *FS) Open(name string) (*File, error) {
	i, ok := fsys.index[name]
	if !ok {
		return nil, fs.ErrNotExist
	}

	f := fsys.files[i]
	if f.Size != 0 {
		// TODO: Make this safe to open multiple files.
		if _, err := fsys.r.Seek(f.Offset, io.SeekStart); err != nil {
			return nil, err
		}
	}
	return &File{
		fsys:   fsys,
		Entry:  f,
		Reader: io.LimitReader(fsys.r, f.Size),
	}, nil
}

func (fsys *FS) Entries() []Entry {
	return fsys.files
}

func NewFS(r io.ReadSeekCloser) (*FS, error) {
	fsys := &FS{
		r:     r,
		files: []Entry{},
		index: map[string]int{},
	}

	cr := &countReader{bufio.NewReaderSize(r, 1<<20), 0}
	tr := tar.NewReader(cr)

	// TODO: Consider caching this if it takes too long.
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		fsys.index[hdr.Name] = len(fsys.files)
		fsys.files = append(fsys.files, Entry{
			Header: *hdr,
			Offset: cr.n,
		})
	}

	return fsys, nil
}

type countReader struct {
	r io.Reader
	n int64
}

func (cr *countReader) Read(p []byte) (int, error) {
	n, err := cr.r.Read(p)
	cr.n += int64(n)
	return n, err
}
