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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"gitlab.alpinelinux.org/alpine/go/pkg/repository"
	"go.lsp.dev/uri"
	"go.opentelemetry.io/otel"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"

	apkfs "github.com/chainguard-dev/go-apk/pkg/fs"
	logger "github.com/chainguard-dev/go-apk/pkg/logger"
)

type APK struct {
	arch              string
	version           string
	logger            logger.Logger
	fs                apkfs.FullFS
	executor          Executor
	ignoreMknodErrors bool
	client            *http.Client
	cache             *cache
	ignoreSignatures  bool
}

func New(options ...Option) (*APK, error) {
	opt := defaultOpts()
	for _, o := range options {
		if err := o(opt); err != nil {
			return nil, err
		}
	}
	return &APK{
		fs:                opt.fs,
		logger:            opt.logger,
		arch:              opt.arch,
		executor:          opt.executor,
		ignoreMknodErrors: opt.ignoreMknodErrors,
		version:           opt.version,
		cache:             opt.cache,
	}, nil
}

type directory struct {
	path  string
	perms os.FileMode
}
type file struct {
	path     string
	perms    os.FileMode
	contents []byte
}

type deviceFile struct {
	path  string
	major uint32
	minor uint32
	perms os.FileMode
}

var baseDirectories = []directory{
	{"/tmp", 0o777 | fs.ModeSticky},
	{"/etc", 0o755},
	{"/lib", 0o755},
	{"/proc", 0o555},
	{"/var", 0o755},
}

var tigerBaseDirectories = []directory{
	{"tmp", 0o777 | fs.ModeSticky},
	{"dev", 0o755},
	{"etc", 0o755},
	{"lib", 0o755},
	{"proc", 0o555},
	{"var", 0o755},
}

// directories is a list of directories to create relative to the root. It will not do MkdirAll, so you
// must include the parent.
// It assumes that the following directories already exist:
//
//		/var
//		/lib
//		/tmp
//		/dev
//		/etc
//	    /proc
var initDirectories = []directory{
	{"/etc/apk", 0o755},
	{"/etc/apk/keys", 0o755},
	{"/lib/apk", 0o755},
	{"/lib/apk/db", 0o755},
	{"/var/cache", 0o755},
	{"/var/cache/apk", 0o755},
	{"/var/cache/misc", 0o755},
}

var tigerInitDirectories = []directory{
	{"etc/apk", 0o755},
	{"etc/apk/keys", 0o755},
	{"lib/apk", 0o755},
	{"lib/apk/db", 0o755},
	{"var/cache", 0o755},
	{"var/cache/apk", 0o755},
	{"var/cache/misc", 0o755},
}

// files is a list of files to create relative to the root, as well as optional content.
// We will not do MkdirAll for the parent dir it is in, so it must exist.
var initFiles = []file{
	{"/etc/apk/world", 0o644, []byte("\n")},
	{"/etc/apk/repositories", 0o644, []byte("\n")},
	{"/lib/apk/db/lock", 0o600, nil},
	{"/lib/apk/db/triggers", 0o644, nil},
	{"/lib/apk/db/installed", 0o644, nil},
}

// files is a list of files to create relative to the root, as well as optional content.
// We will not do MkdirAll for the parent dir it is in, so it must exist.
var tigerInitFiles = []file{
	{"lib/apk/db/lock", 0o600, nil},
}

// deviceFiles is a list of files to create relative to the root.
var initDeviceFiles = []deviceFile{
	{"/dev/zero", 1, 5, 0o666},
	{"/dev/urandom", 1, 9, 0o666},
	{"/dev/null", 1, 3, 0o666},
	{"/dev/random", 1, 8, 0o666},
	{"/dev/console", 5, 1, 0o620},
}

var tigerInitDeviceFiles = []deviceFile{
	{"dev/zero", 1, 5, 0o666},
	{"dev/urandom", 1, 9, 0o666},
	{"dev/null", 1, 3, 0o666},
	{"dev/random", 1, 8, 0o666},
	{"dev/console", 5, 1, 0o620},
}

// SetClient set the http client to use for downloading packages.
// In general, you can leave this unset, and it will use the default http.Client.
// It is useful for fine-grained control, for proxying, or for setting alternate
// paths.
func (a *APK) SetClient(client *http.Client) {
	a.client = client
}

// ListInitFiles list the files that are installed during the InitDB phase.
func (a *APK) ListInitFiles() []tar.Header {
	var headers = make([]tar.Header, 0, 20)

	// additionalFiles are files we need but can only be resolved in the context of
	// this func, e.g. we need the architecture
	additionalFiles := []file{
		{"/etc/apk/arch", 0o644, []byte(a.arch + "\n")},
	}

	for _, e := range initDirectories {
		headers = append(headers, tar.Header{
			Name:     e.path,
			Mode:     int64(e.perms),
			Typeflag: tar.TypeDir,
			Uid:      0,
			Gid:      0,
		})
	}
	for _, e := range append(initFiles, additionalFiles...) {
		headers = append(headers, tar.Header{
			Name:     e.path,
			Mode:     int64(e.perms),
			Typeflag: tar.TypeReg,
			Uid:      0,
			Gid:      0,
		})
	}
	for _, e := range initDeviceFiles {
		headers = append(headers, tar.Header{
			Name:     e.path,
			Typeflag: tar.TypeChar,
			Mode:     int64(e.perms),
			Uid:      0,
			Gid:      0,
		})
	}

	// add scripts.tar with nothing in it
	headers = append(headers, tar.Header{
		Name:     scriptsFilePath,
		Mode:     int64(scriptsTarPerms),
		Typeflag: tar.TypeReg,
		Uid:      0,
		Gid:      0,
	})

	return headers
}

func AppendInitFiles(tw *tar.Writer, arch string) error {
	// TODO(jonjohnsonjr): Do this once (minus the arch).
	headers := make([]tar.Header, 0, len(tigerBaseDirectories)+len(tigerInitDirectories)+len(tigerInitFiles)+len(tigerInitDeviceFiles)+1)

	for _, e := range tigerBaseDirectories {
		headers = append(headers, tar.Header{
			Name:     e.path,
			Mode:     int64(e.perms),
			Typeflag: tar.TypeDir,
			Uid:      0,
			Gid:      0,
		})
	}

	for _, e := range tigerInitDirectories {
		headers = append(headers, tar.Header{
			Name:     e.path,
			Mode:     int64(e.perms),
			Typeflag: tar.TypeDir,
			Uid:      0,
			Gid:      0,
		})
	}
	for _, e := range tigerInitFiles {
		headers = append(headers, tar.Header{
			Name:     e.path,
			Mode:     int64(e.perms),
			Typeflag: tar.TypeReg,
			Uid:      0,
			Gid:      0,
		})
	}
	for _, e := range tigerInitDeviceFiles {
		headers = append(headers, tar.Header{
			Name:     e.path,
			Typeflag: tar.TypeChar,
			Mode:     int64(e.perms),
			Uid:      0,
			Gid:      0,
		})
	}

	for _, hdr := range headers {
		if err := tw.WriteHeader(&hdr); err != nil {
			return err
		}
	}

	content := []byte(arch + "\n")
	hdr := tar.Header{
		Name:     "etc/apk/arch",
		Typeflag: tar.TypeReg,
		Mode:     0644,
		Size:     int64(len(content)),
		Uid:      0,
		Gid:      0,
	}
	if err := tw.WriteHeader(&hdr); err != nil {
		return err
	}
	if _, err := tw.Write(content); err != nil {
		return err
	}

	return nil
}

// Initialize the APK database for a given build context.
// Assumes base directories are in place and checks them.
// Returns the list of files and directories and files installed and permissions,
// unless those files will be included in the installed database, in which case they can
// be retrieved via GetInstalled().
func (a *APK) InitDB(ctx context.Context, versions ...string) error {
	/*
		equivalent of: "apk add --initdb --arch arch --root root"
	*/
	a.logger.Infof("initializing apk database")

	// additionalFiles are files we need but can only be resolved in the context of
	// this func, e.g. we need the architecture
	additionalFiles := []file{
		{"/etc/apk/arch", 0o644, []byte(a.arch + "\n")},
	}

	for _, e := range baseDirectories {
		stat, err := a.fs.Stat(e.path)
		switch {
		case err != nil && errors.Is(err, fs.ErrNotExist):
			err := a.fs.Mkdir(e.path, e.perms)
			if err != nil {
				return fmt.Errorf("failed to create base directory %s: %w", e.path, err)
			}
		case err != nil:
			return fmt.Errorf("error opening base directory %s: %w", e.path, err)
		case !stat.IsDir():
			return fmt.Errorf("base directory %s is not a directory", e.path)
		case stat.Mode().Perm() != e.perms:
			got, want := stat.Mode().Perm(), e.perms
			return fmt.Errorf("base directory %s has incorrect permissions: got %o want %o ", e.path, got, want)
		}
	}
	for _, e := range initDirectories {
		err := a.fs.Mkdir(e.path, e.perms)
		switch {
		case err != nil && !errors.Is(err, fs.ErrExist):
			return fmt.Errorf("failed to create directory %s: %w", e.path, err)
		case err != nil && errors.Is(err, fs.ErrExist):
			stat, err := a.fs.Stat(e.path)
			if err != nil {
				return fmt.Errorf("failed to stat directory %s: %w", e.path, err)
			}
			if !stat.IsDir() {
				return fmt.Errorf("failed to create directory %s: already exists as file", e.path)
			}
		}
	}
	for _, e := range append(initFiles, additionalFiles...) {
		if err := a.fs.WriteFile(e.path, e.contents, e.perms); err != nil {
			return fmt.Errorf("failed to create file %s: %w", e.path, err)
		}
	}
	for _, e := range initDeviceFiles {
		perms := uint32(e.perms.Perm())
		err := a.fs.Mknod(e.path, unix.S_IFCHR|perms, int(unix.Mkdev(e.major, e.minor)))
		if !a.ignoreMknodErrors && err != nil {
			return fmt.Errorf("failed to create char device %s: %w", e.path, err)
		}
	}

	// add scripts.tar with nothing in it
	scriptsTarPerms := 0o644
	tarfile, err := a.fs.OpenFile(scriptsFilePath, os.O_CREATE|os.O_WRONLY, fs.FileMode(scriptsTarPerms))
	if err != nil {
		return fmt.Errorf("could not create tarball file '%s', got error '%w'", scriptsFilePath, err)
	}
	defer tarfile.Close()
	tarWriter := tar.NewWriter(tarfile)
	defer tarWriter.Close()

	// nothing to add to it; scripts.tar should be empty

	// get the alpine-keys base keys for our usage
	if len(versions) != 0 {
		if err := a.fetchAlpineKeys(ctx, versions); err != nil {
			var nokeysErr *NoKeysFoundError
			if !errors.As(err, &nokeysErr) {
				return fmt.Errorf("failed to fetch alpine-keys: %w", err)
			}
			a.logger.Infof("ignoring missing keys: %s", err.Error())
		}
	}

	a.logger.Infof("finished initializing apk database")
	return nil
}

// loadSystemKeyring returns the keys found in the system keyring
// directory by trying some common locations. These can be overridden
// by passing one or more directories as arguments.
func (a *APK) loadSystemKeyring(locations ...string) ([]string, error) {
	var ring []string
	if len(locations) == 0 {
		locations = []string{
			filepath.Join(DefaultSystemKeyRingPath, a.arch),
		}
	}
	for _, d := range locations {
		keyFiles, err := fs.ReadDir(a.fs, d)

		if errors.Is(err, os.ErrNotExist) {
			a.logger.Warnf("%s doesn't exist, skipping...", d)
			continue
		}

		if err != nil {
			return nil, fmt.Errorf("reading keyring directory: %w", err)
		}

		for _, f := range keyFiles {
			ext := filepath.Ext(f.Name())
			p := filepath.Join(d, f.Name())

			if ext == ".pub" {
				ring = append(ring, p)
			} else {
				a.logger.Infof("%s has invalid extension (%s), skipping...", p, ext)
			}
		}
	}
	if len(ring) > 0 {
		return ring, nil
	}
	// Return an error since reading the system keyring is the last resort
	return nil, errors.New("no suitable keyring directory found")
}

// Installs the specified keys into the APK keyring inside the build context.
func (a *APK) InitKeyring(ctx context.Context, keyFiles, extraKeyFiles []string) (err error) {
	a.logger.Infof("initializing apk keyring")
	ctx, span := otel.Tracer("apko").Start(ctx, "InitKeyring")
	defer span.End()

	if err := a.fs.MkdirAll(DefaultKeyRingPath, 0o755); err != nil {
		return fmt.Errorf("failed to make keys dir: %w", err)
	}

	if len(extraKeyFiles) > 0 {
		a.logger.Debugf("appending %d extra keys to keyring", len(extraKeyFiles))
		keyFiles = append(keyFiles, extraKeyFiles...)
	}

	var eg errgroup.Group

	for _, element := range keyFiles {
		element := element
		eg.Go(func() error {
			ctx, span := otel.Tracer("apko").Start(ctx, fmt.Sprintf("InitKeyring(%q)", element))
			defer span.End()
			a.logger.Debugf("installing key %v", element)

			// Normalize the element as a URI, so that local paths
			// are translated into file:// URLs, allowing them to be parsed
			// into a url.URL{}.
			var asURI uri.URI
			if strings.HasPrefix(element, "https://") {
				asURI, _ = uri.Parse(element)
			} else {
				asURI = uri.New(element)
			}
			asURL, err := url.Parse(string(asURI))
			if err != nil {
				return fmt.Errorf("failed to parse key as URI: %w", err)
			}

			var data []byte
			switch asURL.Scheme {
			case "file": //nolint:goconst
				data, err = os.ReadFile(element)
				if err != nil {
					return fmt.Errorf("failed to read apk key: %w", err)
				}
			case "https": //nolint:goconst
				client := a.client
				if client == nil {
					client = &http.Client{}
				}
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, asURL.String(), nil)
				if err != nil {
					return err
				}
				resp, err := client.Do(req)
				if err != nil {
					return fmt.Errorf("failed to fetch apk key: %w", err)
				}
				defer resp.Body.Close()

				if resp.StatusCode < 200 || resp.StatusCode > 299 {
					return errors.New("failed to fetch apk key: http response indicated error")
				}

				data, err = io.ReadAll(resp.Body)
				if err != nil {
					return fmt.Errorf("failed to read apk key response: %w", err)
				}
			default:
				return fmt.Errorf("scheme %s not supported", asURL.Scheme)
			}

			// #nosec G306 -- apk keyring must be publicly readable
			if err := a.fs.WriteFile(filepath.Join("etc", "apk", "keys", filepath.Base(element)), data,
				0o644); err != nil {
				return fmt.Errorf("failed to write apk key: %w", err)
			}

			return nil
		})
	}

	return eg.Wait()
}

// TODO(jonjohnsonjr): Fetch these once per invocation.
func AppendKeyring(ctx context.Context, tw *tar.Writer, keyFiles, extraKeyFiles []string) (err error) {
	ctx, span := otel.Tracer("apko").Start(ctx, "AppendKeyring")
	defer span.End()

	if len(extraKeyFiles) > 0 {
		keyFiles = append(keyFiles, extraKeyFiles...)
	}

	var eg errgroup.Group

	for _, element := range keyFiles {
		element := element
		eg.Go(func() error {
			// Normalize the element as a URI, so that local paths
			// are translated into file:// URLs, allowing them to be parsed
			// into a url.URL{}.
			var asURI uri.URI
			if strings.HasPrefix(element, "https://") {
				asURI, _ = uri.Parse(element)
			} else {
				asURI = uri.New(element)
			}
			asURL, err := url.Parse(string(asURI))
			if err != nil {
				return fmt.Errorf("failed to parse key as URI: %w", err)
			}

			var data []byte
			switch asURL.Scheme {
			case "file": //nolint:goconst
				data, err = os.ReadFile(element)
				if err != nil {
					return fmt.Errorf("failed to read apk key: %w", err)
				}
			case "https": //nolint:goconst
				client := &http.Client{}
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, asURL.String(), nil)
				if err != nil {
					return err
				}
				resp, err := client.Do(req)
				if err != nil {
					return fmt.Errorf("failed to fetch apk key: %w", err)
				}
				defer resp.Body.Close()

				if resp.StatusCode < 200 || resp.StatusCode > 299 {
					return errors.New("failed to fetch apk key: http response indicated error")
				}

				data, err = io.ReadAll(resp.Body)
				if err != nil {
					return fmt.Errorf("failed to read apk key response: %w", err)
				}
			default:
				return fmt.Errorf("scheme %s not supported", asURL.Scheme)
			}

			hdr := tar.Header{
				Name: path.Join("etc", "apk", "keys", path.Base(element)),
				Size: int64(len(data)),
				Mode: 0644,
			}
			// #nosec G306 -- apk keyring must be publicly readable
			if err := tw.WriteHeader(&hdr); err != nil {
				return fmt.Errorf("failed to write header for apk key %s: %w", hdr.Name, err)
			}
			if _, err := tw.Write(data); err != nil {
				return fmt.Errorf("failed to write apk key %s: %w", hdr.Name, err)
			}

			return nil
		})
	}

	return eg.Wait()
}

// ResolveWorld determine the target state for the requested dependencies in /etc/apk/world. Do not install anything.
func (a *APK) ResolveWorld(ctx context.Context) (toInstall []*repository.RepositoryPackage, conflicts []string, err error) {
	ctx, span := otel.Tracer("go-apk").Start(ctx, "ResolveWorld")
	defer span.End()

	a.logger.Infof("determining desired apk world")

	// to fix the world, we need to:
	// 1. Get the apkIndexes for each repository for the target arch
	indexes, err := a.getRepositoryIndexes(ctx, a.ignoreSignatures)
	if err != nil {
		return toInstall, conflicts, fmt.Errorf("error getting repository indexes: %w", err)
	}
	// debugging info, if requested
	a.logger.Debugf("got %d indexes:\n%s", len(indexes), strings.Join(indexNames(indexes), "\n"))

	// 2. Get the dependency tree for each package from the world file
	directPkgs, err := a.GetWorld()
	if err != nil {
		return toInstall, conflicts, fmt.Errorf("error getting world packages: %w", err)
	}
	resolver := NewPkgResolver(indexes)
	toInstall, conflicts, err = resolver.GetPackagesWithDependencies(directPkgs)
	if err != nil {
		return
	}
	a.logger.Debugf("got %d packages to install:\n%s", len(toInstall), strings.Join(packageRefs(toInstall), "\n"))
	return
}

// FixateWorld force apk's resolver to re-resolve the requested dependencies in /etc/apk/world.
func (a *APK) FixateWorld(ctx context.Context, sourceDateEpoch *time.Time) error {
	ctx, span := otel.Tracer("apko").Start(ctx, "FixateWorld")
	defer span.End()

	/*
		equivalent of: "apk fix --arch arch --root root"
		with possible options for --no-scripts, --no-cache, --update-cache

		current default is: cache=false, updateCache=true, executeScripts=false
	*/
	a.logger.Infof("synchronizing with desired apk world")

	// to fix the world, we need to:
	// 1. Get the apkIndexes for each repository for the target arch
	if err := a.lock(); err != nil {
		return fmt.Errorf("failed to lock: %w", err)
	}
	defer func() {
		_ = a.unlock()
	}()
	allpkgs, conflicts, err := a.ResolveWorld(ctx)
	if err != nil {
		return fmt.Errorf("error getting package dependencies: %w", err)
	}

	// 3. For each name on the list:
	//     a. Check if it is installed, if so, skip
	//     b. Get the .apk file
	//     c. Install the .apk file
	//     d. Update /lib/apk/db/scripts.tar
	//     d. Update /lib/apk/db/triggers
	//     e. Update the installed file
	dir, err := os.MkdirTemp("", "go-apk")
	if err != nil {
		return fmt.Errorf("could not make temp dir: %w", err)
	}
	defer os.RemoveAll(dir)
	for _, pkg := range conflicts {
		isInstalled, err := a.isInstalledPackage(pkg)
		if err != nil {
			return fmt.Errorf("error checking if package %s is installed: %w", pkg, err)
		}
		if isInstalled {
			return fmt.Errorf("cannot install due to conflict with %s", pkg)
		}
	}
	for _, pkg := range allpkgs {
		isInstalled, err := a.isInstalledPackage(pkg.Name)
		if err != nil {
			return fmt.Errorf("error checking if package %s is installed: %w", pkg.Name, err)
		}
		if isInstalled {
			continue
		}
		// get the apk file
		if err := a.installPackage(ctx, pkg, sourceDateEpoch); err != nil {
			return err
		}
	}
	return nil
}

type NoKeysFoundError struct {
	arch     string
	releases []string
}

func (e *NoKeysFoundError) Error() string {
	return fmt.Sprintf("no keys found for arch %s and releases %v", e.arch, e.releases)
}

// fetchAlpineKeys fetches the public keys for the repositories in the APK database.
func (a *APK) fetchAlpineKeys(ctx context.Context, versions []string) error {
	ctx, span := otel.Tracer("apko").Start(ctx, "fetchAlpineKeys")
	defer span.End()
	u := alpineReleasesURL
	client := a.client
	if client == nil {
		client = &http.Client{}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch alpine releases: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("unable to get alpine releases at %s: %v", u, res.Status)
	}
	b, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("failed to read alpine releases: %w", err)
	}
	var releases Releases
	if err := json.Unmarshal(b, &releases); err != nil {
		return fmt.Errorf("failed to unmarshal alpine releases: %w", err)
	}
	// what is the alpine version we use?
	var alpineVersions = versions
	if len(alpineVersions) == 0 {
		alpineVersions = append(alpineVersions, releases.LatestStable)
	}
	var urls []string
	// now just need to get the keys for the desired architecture and releases
	for _, version := range alpineVersions {
		branch := releases.GetReleaseBranch(version)
		if branch == nil {
			continue
		}
		urls = append(urls, branch.KeysFor(a.arch, time.Now())...)
	}
	if len(urls) == 0 {
		return &NoKeysFoundError{arch: a.arch, releases: alpineVersions}
	}
	// get the keys for each URL and save them to a file with that name
	for _, u := range urls {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return err
		}
		res, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("failed to fetch alpine key %s: %w", u, err)
		}
		defer res.Body.Close()
		basefilenameEscape := filepath.Base(u)
		basefilename, err := url.PathUnescape(basefilenameEscape)
		if err != nil {
			return fmt.Errorf("failed to unescape key filename %s: %w", basefilenameEscape, err)
		}
		filename := filepath.Join(keysDirPath, basefilename)
		f, err := a.fs.OpenFile(filename, os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return fmt.Errorf("failed to open key file %s: %w", filename, err)
		}
		defer f.Close()
		if _, err := io.Copy(f, res.Body); err != nil {
			return fmt.Errorf("failed to write key file %s: %w", filename, err)
		}
	}
	return nil
}

// TODO(jonjohnsonjr): Fetch these once per invocation and cache them.
func AppendAlpineKeys(ctx context.Context, tw *tar.Writer, arch string, versions []string) error {
	ctx, span := otel.Tracer("apko").Start(ctx, "fetchAlpineKeys")
	defer span.End()
	u := alpineReleasesURL
	client := &http.Client{}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch alpine releases: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("unable to get alpine releases at %s: %v", u, res.Status)
	}
	b, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("failed to read alpine releases: %w", err)
	}
	var releases Releases
	if err := json.Unmarshal(b, &releases); err != nil {
		return fmt.Errorf("failed to unmarshal alpine releases: %w", err)
	}
	// what is the alpine version we use?
	var alpineVersions = versions
	if len(alpineVersions) == 0 {
		alpineVersions = append(alpineVersions, releases.LatestStable)
	}
	var urls []string
	// now just need to get the keys for the desired architecture and releases
	for _, version := range alpineVersions {
		branch := releases.GetReleaseBranch(version)
		if branch == nil {
			continue
		}
		urls = append(urls, branch.KeysFor(arch, time.Now())...)
	}
	if len(urls) == 0 {
		return &NoKeysFoundError{arch: arch, releases: alpineVersions}
	}
	// get the keys for each URL and save them to a file with that name
	for _, u := range urls {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return err
		}
		res, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("failed to fetch alpine key %s: %w", u, err)
		}
		defer res.Body.Close()
		basefilenameEscape := path.Base(u)
		basefilename, err := url.PathUnescape(basefilenameEscape)
		if err != nil {
			return fmt.Errorf("failed to unescape key filename %s: %w", basefilenameEscape, err)
		}
		filename := path.Join(keysDirPath, basefilename)
		hdr := tar.Header{
			Name: filename,
			Size: res.ContentLength,
			Mode: 0644,
		}
		if err := tw.WriteHeader(&hdr); err != nil {
			return fmt.Errorf("failed to write header for %s: %w", filename, err)
		}
		if _, err := io.Copy(tw, res.Body); err != nil {
			return fmt.Errorf("failed to write key file %s: %w", filename, err)
		}
	}
	return nil
}

// installPkg install a single package and update installed db.
//

func (a *APK) installPackage(ctx context.Context, pkg *repository.RepositoryPackage, sourceDateEpoch *time.Time) error {
	a.logger.Debugf("installing %s (%s)", pkg.Name, pkg.Version)

	r, err := a.fetchPackage(ctx, pkg)
	if err != nil {
		return err
	}
	defer r.Close()

	// install the apk file
	expanded, err := ExpandApk(ctx, r)
	if err != nil {
		return fmt.Errorf("unable to expand apk for package %s: %w", pkg.Name, err)
	}
	defer expanded.Close()
	installedFiles, err := a.installAPKFiles(ctx, expanded.PackageData, pkg.Origin, pkg.Replaces)
	if err != nil {
		return fmt.Errorf("unable to install files for pkg %s: %w", pkg.Name, err)
	}

	// update the scripts.tar
	controlData := bytes.NewReader(expanded.ControlData)

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

func packageRefs(pkgs []*repository.RepositoryPackage) []string {
	names := make([]string, len(pkgs))
	for i, pkg := range pkgs {
		names[i] = fmt.Sprintf("%s (%s) %s", pkg.Name, pkg.Version, pkg.Url())
	}
	return names
}

// Normalize the repo as a URI, so that local paths
// are translated into file:// URLs, allowing them to be parsed
// into a url.URL{}.
func (a *APK) url(u string) (*url.URL, error) {
	if !strings.HasPrefix(u, "https://") {
		return url.Parse(string(uri.New(u)))
	}
	asURI, err := uri.Parse(u)
	if err != nil {
		return nil, fmt.Errorf("parsing uri %q: %w", u, err)
	}

	return url.Parse(string(asURI))
}

func (a *APK) fetchPackage(ctx context.Context, pkg *repository.RepositoryPackage) (io.ReadCloser, error) {
	ctx, span := otel.Tracer("go-apk").Start(ctx, "fetchPackage")
	defer span.End()

	u := pkg.Url()
	asURL, err := a.url(u)
	if err != nil {
		return nil, fmt.Errorf("parsing %q: %w", u, err)
	}

	switch asURL.Scheme {
	case "file":
		return os.Open(u)
	case "https":
		client := a.client
		if client == nil {
			client = &http.Client{}
		}
		if a.cache != nil {
			client = a.cache.client(client, false)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		res, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("unable to get package apk at %s: %w", u, err)
		}
		if res.StatusCode != http.StatusOK {
			defer res.Body.Close()
			return nil, fmt.Errorf("unable to get package apk at %s: %v", u, res.Status)
		}
		return res.Body, nil
	}

	return nil, fmt.Errorf("repository scheme %s not supported", asURL.Scheme)
}
