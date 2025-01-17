# go-apk

A native go implementation of the functionality of the [Alpine Package Keeper](https://wiki.alpinelinux.org/wiki/Alpine_Package_Keeper)
client utility `apk`.

Also includes supporting utilities for working with filesystems, including:

* an interface for a fully functional [fs.FS](https://pkg.go.dev/io/fs#FS) with
read-write, chmod/chown, devices, and symlinks capabilities
* an implementation of that FS in memory, i.e. a memfs
* an implementation of that FS on top of a directory, which uses the memfs for features the underlying disk does not support
* tarball features

Documentation is available at [https://pkg.go.dev/github.com/chainguard-dev/go-apk](https://pkg.go.dev/github.com/chainguard-dev/go-apk).

## Usage

```go
import (
    "github.com/chainguard-dev/go-apk/pkg/apk"
    "github.com/chainguard-dev/go-apk/pkg/fs"
)

fsys := fs.NewMemFS()
a, err := apk.New(
		apk.WithFS(fsys),
		apk.WithArch("aarch64"),
	)
a.InitDB("3.16", "3.17") // ensure basic structures and set up the database, fetches keys for those OS versions
a.InitKeyring([]string{"/etc/apk/keyfiles/key1"}, nil)
a.SetRepositories([]string{"https://dl-cdn.alpinelinux.org/alpine/v3.14/main"})
a.SetWorld([]string{"curl", "vim"})    // set the packages in /etc/apk/world
a.FixateWorld()              // install packages based on the contents of /etc/apk/world
```

Wherever possible the methods on `apk` that manipulate data are available standalone,
so you can work with them outside of a given `FullFS`.

## Components

### Filesystems

The native go [fs.FS](https://pkg.go.dev/io/fs#FS) interface is a read-only filesystem
with no support for full capabilities like read-write, let alone symlinks, hardlinks,
chown/chmod, devices, etc.

That makes it useful for reading, but not very useful for cases where you need to lay
down data, like installing packages from a package manager.

`github.com/chainguard-dev/go-apk/pkg/fs` provides a `FullFS` interface that extends the
`fs.FS` interface with full read-write, chmod/chown, devices, and symlinks capabilities.
You can do pretty much anything that you can do with a normal filesystem.

It is fully compliant with [fs.FS](https://pkg.go.dev/io/fs#FS), so you can use it
anywhere an `fs.FS` is required.

It also provides two implementations of that interface:

* `memfs` is an in-memory implementation of `FullFS`. It is fully functional, but remember that it uses memory, so loading very large files into it will hit limits.
* `rwosfs` is an on-disk implementation of `FullFS`. It is fully functional, including capabilities that may not exist on the underlying filesystem, like symlinks, devices, chown/chmod and case-sensitivity. The metadata for every file on disk also is in-memory, enabling those additional capabilities. Contents are not stored in memory.

### Tarball

`github.com/chainguard-dev/go-apk/pkg/tarball` provides a utility to write an [fs.FS](https://pkg.go.dev/io/fs#FS) to a tarball. It is implemented on a `tarball.Context`, which lets
you provide overrides for timestamps, UID/GID, and other features.

### apk

`github.com/chainguard-dev/go-apk/pkg/apk` is the heart of this library. It provides a native go
implementation of the functionality of the
[Alpine Package Keeper](https://wiki.alpinelinux.org/wiki/Alpine_Package_Keeper)
with regards to reading repositories, installing packages, and managing a local install.
