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
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/chainguard-dev/go-apk/pkg/tarball"
	"gitlab.alpinelinux.org/alpine/go/pkg/repository"
	"golang.org/x/sys/unix"
)

const (
	pathSep = "/"
	// maxLinks maximum permitted depths of symlinks, to prevent infinite recursion
	// matches what Linux kernel does from 4.2 onwards, see https://man7.org/linux/man-pages/man7/path_resolution.7.html
	maxLinks = 40
)

type FullFS interface {
	Mkdir(path string, perm fs.FileMode) error
	MkdirAll(path string, perm fs.FileMode) error
	Open(name string) (fs.File, error)
	OpenReaderAt(name string) (File, error)
	OpenFile(name string, flag int, perm fs.FileMode) (File, error)
	ReadFile(name string) ([]byte, error)
	WriteFile(name string, b []byte, mode fs.FileMode) error
	ReadDir(name string) ([]fs.DirEntry, error)
	Mknod(path string, mode uint32, dev int) error
	Readnod(name string) (dev int, err error)
	Symlink(oldname, newname string) error
	Link(oldname, newname string) error
	Readlink(name string) (target string, err error)
	Stat(path string) (fs.FileInfo, error)
	Lstat(path string) (fs.FileInfo, error)
	Create(name string) (File, error)
	Remove(name string) error
	Chmod(path string, perm fs.FileMode) error
	Chown(path string, uid int, gid int) error

	WriteHeader(hdr tar.Header, tfs *tarball.FS, offset int64, pkg *repository.Package) error
}

// File is an interface for a file. It includes Read, Write, Close.
// This wouldn't be necessary if os.File were an interface, or if fs.File
// were read/write.
type File interface {
	fs.File
	io.WriteSeeker
	io.ReaderAt
}

type tarEntry struct {
	tfs      *tarball.FS
	offset   int64
	header   tar.Header
	checksum []byte
	pkg      *repository.Package
}

type memFS struct {
	tree *node
	hdrs map[[20]byte]tarEntry
}

func NewMemFS() FullFS {
	return &memFS{
		tree: &node{
			dir:      true,
			children: map[string]*node{},
			name:     "/",
			mode:     fs.ModeDir | 0o755,
		},
		hdrs: map[[20]byte]tarEntry{},
	}
}

func (m *memFS) WriteHeader(hdr tar.Header, tfs *tarball.FS, offset int64, pkg *repository.Package) error {
	switch hdr.Typeflag {
	case tar.TypeDir:
		// special case, if the target already exists, and it is a symlink to a directory, we can accept it as is
		// otherwise, we need to create the directory.
		if fi, err := m.Stat(hdr.Name); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			if target, err := m.Readlink(hdr.Name); err == nil {
				if fi, err = m.Stat(target); err == nil && fi.IsDir() {
					// "break" rather than "continue", so that any handling outside of this switch statement is processed
					break
				}
			}
		}
		if err := m.MkdirAll(hdr.Name, hdr.FileInfo().Mode().Perm()); err != nil {
			return fmt.Errorf("error creating directory %s: %w", hdr.Name, err)
		}

	case tar.TypeReg:
		// We trust this because we verify it earlier in ExpandAPK.
		checksum, err := checksumFromHeader(&hdr)
		if err != nil {
			return err
		}

		if checksum == nil {
			return fmt.Errorf("checksum is nil for %s", hdr.Name)
		}

		te := tarEntry{
			tfs:      tfs,
			offset:   offset,
			header:   hdr,
			checksum: checksum,
			pkg:      pkg,
		}

		return m.writeHeader(hdr.Name, te)

	case tar.TypeSymlink:
		// some underlying filesystems and some memfs that we use in tests do not support symlinks.
		// attempt it, and if it fails, just copy it.
		// if it already exists, pointing to the same target, we can ignore it
		if target, err := m.Readlink(hdr.Name); err == nil && target == hdr.Linkname {
			return nil
		}
		if err := m.Symlink(hdr.Linkname, hdr.Name); err != nil {
			return fmt.Errorf("unable to install symlink from %s -> %s: %w", hdr.Name, hdr.Linkname, err)
		}
	case tar.TypeLink:
		if err := m.Link(hdr.Linkname, hdr.Name); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported file type %s %v", hdr.Name, hdr.Typeflag)
	}

	return nil
}

// getNode returns the node for the given path. If the path is not found, it
// returns an error.
func (m *memFS) getNode(path string) (*node, error) {
	return m.getNodeCountLinks(path, 0)
}

func (m *memFS) getNodeCountLinks(path string, linkDepth int) (*node, error) {
	if path == "/" || path == "." {
		return m.tree, nil
	}
	parts := strings.Split(path, pathSep)
	node := m.tree
	traversed := make([]string, 0)
	for _, part := range parts {
		if part == "" {
			continue
		}
		if node.children == nil {
			return nil, fs.ErrNotExist
		}
		var ok bool
		node.mu.Lock()
		childNode, ok := node.children[part]
		// immediately unlock, no need to wait for defer. This is *really* important in the
		// case of symlinks below
		node.mu.Unlock()
		if !ok {
			return nil, fs.ErrNotExist
		}
		// what if it is a symlink?
		if childNode.mode&os.ModeSymlink != 0 {
			newDepth := linkDepth + 1
			if newDepth > maxLinks {
				return nil, fmt.Errorf("maximum symlink depth exceeded")
			}
			// getNode requires working on the absolute path, so we just resolve the path to an absolute path,
			// rather than struggling to clean up the path.
			// But, we have to make sure that we set it relative to where we are currently, rather than the parent of the path.
			// For example, /usr/lib64/foo/bar when /usr/lib64 -> lib, we want to resolve to /usr/lib rather than /usr/lib64/foo/lib
			linkTarget := childNode.linkTarget
			if !filepath.IsAbs(linkTarget) {
				linkTarget = filepath.Join(strings.Join(traversed, pathSep), linkTarget)
			}
			// now we have the absolute path, we can get the node
			// but that absolute path can cause us to try and hit something that is already locked
			// and since we are recursing, it will not get freed until we return
			// leading to a deadlock race condition
			targetNode, err := m.getNodeCountLinks(linkTarget, newDepth)
			if err != nil {
				return nil, err
			}
			childNode = targetNode
		}
		node = childNode
		traversed = append(traversed, part)
	}
	return node, nil
}

func (m *memFS) Mkdir(path string, perms fs.FileMode) error {
	// first see if the parent exists
	parent := filepath.Dir(path)
	anode, err := m.getNode(parent)
	if err != nil {
		return err
	}
	if anode.mode&fs.ModeDir == 0 {
		return fmt.Errorf("parent is not a directory")
	}
	// see if it exists
	anode.mu.Lock()
	defer anode.mu.Unlock()
	if _, ok := anode.children[filepath.Base(path)]; ok {
		return fs.ErrExist
	}
	// now create the directory
	anode.children[filepath.Base(path)] = &node{
		name:       filepath.Base(path),
		mode:       fs.ModeDir | perms,
		dir:        true,
		modTime:    time.Now(),
		createTime: time.Now(),
		children:   map[string]*node{},
	}
	return nil
}

func (m *memFS) Stat(path string) (fs.FileInfo, error) {
	node, err := m.getNode(path)
	if err != nil {
		return nil, err
	}
	if node.mode&fs.ModeSymlink != 0 {
		targetNode, err := m.getNode(node.linkTarget)
		if err != nil {
			return nil, err
		}
		node = targetNode
	}
	return node.fileInfo(path), nil
}

func (m *memFS) Lstat(path string) (fs.FileInfo, error) {
	node, err := m.getNode(path)
	if err != nil {
		return nil, err
	}
	return node.fileInfo(path), nil
}

func (m *memFS) MkdirAll(path string, perm fs.FileMode) error {
	parts := strings.Split(path, pathSep)
	traversed := make([]string, 0)
	anode := m.tree
	for _, part := range parts {
		if part == "" {
			continue
		}
		if anode.children == nil {
			anode.children = map[string]*node{}
		}
		var ok bool
		anode.mu.Lock()
		newnode, ok := anode.children[part]
		if !ok {
			newnode = &node{
				name:       part,
				mode:       fs.ModeDir | perm,
				dir:        true,
				modTime:    time.Now(),
				createTime: time.Now(),
				children:   map[string]*node{},
			}
			anode.children[part] = newnode
		}
		anode.mu.Unlock()
		// what if it is a symlink?
		if newnode.mode&os.ModeSymlink != 0 {
			linkTarget := newnode.linkTarget
			if !filepath.IsAbs(linkTarget) {
				linkTarget = filepath.Join(strings.Join(traversed, pathSep), linkTarget)
			}

			targetNode, err := m.getNode(linkTarget)
			if err != nil {
				return err
			}
			newnode = targetNode
		}
		if !newnode.dir {
			return fmt.Errorf("path is not a directory")
		}
		anode = newnode
		traversed = append(traversed, part)
	}
	return nil
}

func (m *memFS) Open(name string) (fs.File, error) {
	return m.OpenFile(name, os.O_RDONLY, 0o644)
}

func (m *memFS) OpenFile(name string, flag int, perm fs.FileMode) (File, error) {
	return m.openFile(name, flag, perm, 0)
}

func (m *memFS) openFile(name string, flag int, perm fs.FileMode, linkCount int) (File, error) {
	parent := filepath.Dir(name)
	base := filepath.Base(name)
	parentAnode, err := m.getNode(parent)
	if err != nil {
		return nil, err
	}
	if !parentAnode.dir {
		return nil, fmt.Errorf("parent is not a directory")
	}
	if parentAnode.children == nil {
		parentAnode.children = map[string]*node{}
	}
	parentAnode.mu.Lock()
	anode, ok := parentAnode.children[base]
	if !ok && flag&os.O_CREATE == 0 {
		parentAnode.mu.Unlock()
		return nil, fs.ErrNotExist
	}
	if anode != nil && anode.dir {
		parentAnode.mu.Unlock()
		return nil, fmt.Errorf("is a directory")
	}
	if flag&os.O_CREATE != 0 {
		if !ok {
			// create the file
			anode = &node{
				name:       base,
				mode:       perm,
				dir:        false,
				modTime:    time.Now(),
				createTime: time.Now(),
			}
			parentAnode.children[base] = anode
		}
	}
	parentAnode.mu.Unlock()
	// what if it is a symlink? Follow the symlink
	if anode.mode&os.ModeSymlink != 0 {
		localCount := linkCount + 1
		if localCount > maxLinks {
			return nil, fmt.Errorf("too many links")
		}
		linkTarget := anode.linkTarget
		if !filepath.IsAbs(linkTarget) {
			linkTarget = filepath.Join(parent, linkTarget)
		}
		return m.openFile(linkTarget, flag, perm, localCount)
	}

	// This came from WriteHeader and we haven't modified it.
	if anode.te != nil && len(anode.data) == 0 {
		// If we're not editing the file, defer to the (read-only) tar file.
		if flag&os.O_CREATE == 0 {
			f, err := anode.te.tfs.Open(anode.te.header.Name)
			if err != nil {
				return nil, err
			}
			f.Entry.Uid = anode.uid
			f.Entry.Gid = anode.gid
			f.Entry.Uname = ""
			f.Entry.Gname = ""
			f.Entry.Mode = int64(anode.mode)

			return f, nil
		}

		// Otherwise, buffer the contents and return an in-mem file.
		if anode.te.header.Size != 0 {
			f, err := anode.te.tfs.Open(anode.te.header.Name)
			if err != nil {
				return nil, err
			}
			data, err := io.ReadAll(f)
			if err != nil {
				return nil, err
			}
			anode.data = data
		}
	}

	return newMemFile(anode, name, m, flag), nil
}

func (m *memFS) writeHeader(name string, te tarEntry) error {
	parent := filepath.Dir(name)
	base := filepath.Base(name)

	parentAnode, err := m.getNode(parent)
	if err != nil {
		return err
	}

	if !parentAnode.dir {
		return fmt.Errorf("parent is not a directory")
	}
	if parentAnode.children == nil {
		parentAnode.children = map[string]*node{}
	}
	existing, ok := parentAnode.children[base]
	if !ok {
		// create the file
		anode := &node{
			name:       base,
			mode:       te.header.FileInfo().Mode(),
			dir:        false,
			modTime:    time.Now(),
			createTime: time.Now(),
			te:         &te,
		}
		parentAnode.children[base] = anode
		return nil
	}

	want, got := te, existing.te

	if got == nil {
		return fmt.Errorf("conflicting file for %q has no tar entry", name)
	}

	// Files have the same checksum, that's fine.
	if bytes.Equal(got.checksum, want.checksum) {
		return nil
	}

	// At this point we know the files conflict, but it's okay if this file replaces that one.
	if got.pkg.Origin != want.pkg.Origin {
		return fmt.Errorf("conflicting file %q in %q has different origin %q != %q in %q", name, got.pkg.Name, got.pkg.Origin, want.pkg.Origin, want.pkg.Name)
	}
	if existing.te.pkg.Name != te.pkg.Replaces {
		return fmt.Errorf("conflicting file %q in %q is not replaced by %q", name, got.pkg.Name, te.pkg.Name)
	}

	anode := &node{
		name:       base,
		mode:       te.header.FileInfo().Mode(),
		dir:        false,
		modTime:    time.Now(),
		createTime: time.Now(),
		te:         &te,
	}
	parentAnode.children[base] = anode

	// If we got here, they're different, but want replaces got, so it's all cool.
	return nil
}

func (m *memFS) ReadFile(name string) ([]byte, error) {
	f, err := m.OpenFile(name, os.O_RDONLY, 0o644)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b := bytes.NewBuffer(nil)
	if _, err := io.Copy(b, f); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func (m *memFS) WriteFile(name string, b []byte, mode fs.FileMode) error {
	f, err := m.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.Copy(f, bytes.NewBuffer(b)); err != nil {
		return err
	}
	return nil
}

func (m *memFS) ReadDir(name string) ([]fs.DirEntry, error) {
	anode, err := m.getNode(name)
	if err != nil {
		return nil, err
	}
	if !anode.dir {
		return nil, fmt.Errorf("not a directory")
	}
	var de = make([]fs.DirEntry, 0, len(anode.children))
	for name, node := range anode.children {
		de = append(de, fs.FileInfoToDirEntry(node.fileInfo(name)))
	}
	// we need them in a consistent order, so sort them by filename, which is what os.ReadDir() does
	sort.Slice(de, func(i, j int) bool {
		return de[i].Name() < de[j].Name()
	})
	return de, nil
}

func (m *memFS) OpenReaderAt(name string) (File, error) {
	return m.OpenFile(name, os.O_RDONLY, 0o644)
}

func (m *memFS) Mknod(path string, mode uint32, dev int) error {
	parent := filepath.Dir(path)
	base := filepath.Base(path)
	anode, err := m.getNode(parent)
	if err != nil {
		return err
	}
	anode.mu.Lock()
	defer anode.mu.Unlock()
	if _, ok := anode.children[base]; ok {
		return fs.ErrExist
	}
	anode.children[base] = &node{
		name:       base,
		mode:       fs.FileMode(mode) | os.ModeCharDevice | os.ModeDevice,
		modTime:    time.Now(),
		createTime: time.Now(),
		major:      unix.Major(uint64(dev)),
		minor:      unix.Minor(uint64(dev)),
	}

	return nil
}

func (m *memFS) Readnod(path string) (dev int, err error) {
	parent := filepath.Dir(path)
	base := filepath.Base(path)
	parentNode, err := m.getNode(parent)
	if err != nil {
		return 0, err
	}
	parentNode.mu.Lock()
	defer parentNode.mu.Unlock()
	anode, ok := parentNode.children[base]
	if !ok {
		return 0, fs.ErrNotExist
	}
	if anode.mode&os.ModeDevice != os.ModeDevice || anode.mode&os.ModeCharDevice != os.ModeCharDevice {
		return 0, fmt.Errorf("not a device")
	}
	return int(unix.Mkdev(anode.major, anode.minor)), nil
}

func (m *memFS) Chmod(path string, perm fs.FileMode) error {
	anode, err := m.getNode(path)
	if err != nil {
		return err
	}
	// need to change the mode, but keep the type
	anode.mode = perm | (anode.mode & os.ModeType)
	return nil
}
func (m *memFS) Chown(path string, uid, gid int) error {
	anode, err := m.getNode(path)
	if err != nil {
		return err
	}
	anode.uid = uid
	anode.gid = gid
	return nil
}

func (m *memFS) Create(name string) (File, error) {
	return m.OpenFile(name, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o666)
}

func (m *memFS) Symlink(oldname, newname string) error {
	parent := filepath.Dir(newname)
	base := filepath.Base(newname)
	anode, err := m.getNode(parent)
	if err != nil {
		return err
	}
	anode.mu.Lock()
	defer anode.mu.Unlock()
	if _, ok := anode.children[base]; ok {
		return fs.ErrExist
	}
	anode.children[base] = &node{
		name:       base,
		mode:       0o777 | os.ModeSymlink,
		modTime:    time.Now(),
		linkTarget: oldname,
	}
	return nil
}

func (m *memFS) Link(oldname, newname string) error {
	parent := filepath.Dir(newname)
	base := filepath.Base(newname)
	anode, err := m.getNode(parent)
	if err != nil {
		return err
	}
	target, err := m.getNode(oldname)
	if err != nil {
		return fs.ErrNotExist
	}
	anode.mu.Lock()
	defer anode.mu.Unlock()
	if _, ok := anode.children[base]; ok {
		return fs.ErrExist
	}
	anode.children[base] = target
	target.linkCount++
	return nil
}

func (m *memFS) Readlink(name string) (target string, err error) {
	parent := filepath.Dir(name)
	base := filepath.Base(name)
	parentNode, err := m.getNode(parent)
	if err != nil {
		return "", err
	}
	parentNode.mu.Lock()
	defer parentNode.mu.Unlock()
	anode, ok := parentNode.children[base]
	if !ok {
		return "", fs.ErrNotExist
	}
	if anode.mode&os.ModeSymlink == 0 {
		return "", fmt.Errorf("file is not a link")
	}
	return anode.linkTarget, nil
}

func (m *memFS) Remove(name string) error {
	parent := filepath.Dir(name)
	base := filepath.Base(name)
	anode, err := m.getNode(parent)
	if err != nil {
		return err
	}
	anode.mu.Lock()
	defer anode.mu.Unlock()
	if _, ok := anode.children[base]; !ok {
		return fs.ErrNotExist
	}
	if anode.children[base].linkCount > 0 {
		anode.children[base].linkCount--
	}
	delete(anode.children, base)
	return nil
}

type memFile struct {
	node     *node
	fs       *memFS
	name     string
	offset   int64
	openMode int
}

func newMemFile(node *node, name string, memfs *memFS, openMode int) *memFile {
	m := &memFile{
		node:     node,
		fs:       memfs,
		name:     name,
		openMode: openMode,
	}
	if openMode&os.O_APPEND != 0 {
		m.offset = int64(len(node.data))
	}
	if openMode&os.O_TRUNC != 0 {
		node.data = nil
	}
	return m
}

func (f *memFile) Stat() (fs.FileInfo, error) {
	if f.node == nil || f.fs == nil {
		return nil, fs.ErrClosed
	}
	return f.fs.Stat(f.name)
}

func (f *memFile) Close() error {
	if f.node == nil || f.fs == nil {
		return fs.ErrClosed
	}
	f.fs = nil
	f.node = nil
	return nil
}

func (f *memFile) Read(b []byte) (int, error) {
	if f.node == nil || f.fs == nil {
		return 0, fs.ErrClosed
	}
	if f.offset >= int64(len(f.node.data)) {
		return 0, io.EOF
	}
	n := copy(b, f.node.data[f.offset:])
	f.offset += int64(n)
	return n, nil
}

func (f *memFile) ReadAt(p []byte, off int64) (n int, err error) {
	if f.node == nil || f.fs == nil {
		return 0, fs.ErrClosed
	}
	if off >= int64(len(f.node.data)) {
		return 0, io.EOF
	}
	n = copy(p, f.node.data[off:])
	return n, nil
}
func (f *memFile) Seek(offset int64, whence int) (int64, error) {
	if f.node == nil || f.fs == nil {
		return 0, fs.ErrClosed
	}
	switch whence {
	case io.SeekStart:
		f.offset = offset
	case io.SeekCurrent:
		f.offset += offset
	case io.SeekEnd:
		f.offset = int64(len(f.node.data)) + offset
	default:
		return 0, errors.New("invalid whence")
	}
	return f.offset, nil
}

func (f *memFile) Write(p []byte) (n int, err error) {
	if f.node == nil || f.fs == nil {
		return 0, fs.ErrClosed
	}
	if f.openMode&os.O_APPEND != 0 && f.openMode&os.O_RDWR != 0 && f.openMode&os.O_WRONLY != 0 {
		return 0, errors.New("file not opened in write mode")
	}
	if f.offset+int64(len(p)) > int64(len(f.node.data)) {
		f.node.data = append(f.node.data[:f.offset], p...)
	} else {
		copy(f.node.data[f.offset:], p)
	}
	f.offset += int64(len(p))
	return len(p), nil
}

type node struct {
	mode         fs.FileMode
	uid, gid     int
	dir          bool
	name         string
	data         []byte
	modTime      time.Time
	createTime   time.Time
	linkTarget   string
	linkCount    int // extra links, so 0 means a single pointer. O-based, like most compuuter counting systems.
	major, minor uint32
	children     map[string]*node
	mu           sync.Mutex
	te           *tarEntry
}

func (n *node) fileInfo(name string) fs.FileInfo {
	if n.te != nil {
		hdr := n.te.header
		hdr.Name = filepath.Join(filepath.Dir(hdr.Name), name)
		if len(n.data) != 0 {
			hdr.Size = int64(len(n.data))
		}
		hdr.Uid = n.uid
		hdr.Gid = n.gid
		hdr.Uname = ""
		hdr.Gname = ""

		hdr.Mode = int64(n.mode)
		return hdr.FileInfo()
	}
	return &memFileInfo{
		node: n,
		name: name,
	}
}

type memFileInfo struct {
	*node
	name string
}

func (m *memFileInfo) Name() string {
	return m.name
}
func (m *memFileInfo) Size() int64 {
	return int64(len(m.data))
}
func (m *memFileInfo) Mode() fs.FileMode {
	return m.mode
}
func (m *memFileInfo) ModTime() time.Time {
	return m.modTime
}
func (m *memFileInfo) IsDir() bool {
	return m.dir
}
func (m *memFileInfo) Sys() any {
	return &tar.Header{
		Mode: int64(m.mode),
		Uid:  m.uid,
		Gid:  m.gid,
	}
}
