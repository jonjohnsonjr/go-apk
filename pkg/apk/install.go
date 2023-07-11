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
	"context" //nolint:gosec // this is what apk tools is using
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/chainguard-dev/go-apk/pkg/tarball"
	"gitlab.alpinelinux.org/alpine/go/pkg/repository"
	"go.opentelemetry.io/otel"
)

// installAPKFiles install the files from the APK and return the list of installed files
// and their permissions. Returns a tar.Header because it is a convenient existing
// struct that has all of the fields we need.
func (a *APK) installAPKFiles(ctx context.Context, in io.ReadSeekCloser, pkg *repository.Package) ([]tar.Header, error) { //nolint:gocyclo
	_, span := otel.Tracer("go-apk").Start(ctx, "installAPKFiles")
	defer span.End()

	var files []tar.Header

	tfs, err := tarball.NewFS(in)
	if err != nil {
		return nil, err
	}

	var startedDataSection bool
	for _, header := range tfs.Entries() {
		// per https://git.alpinelinux.org/apk-tools/tree/src/extract_v2.c?id=337734941831dae9a6aa441e38611c43a5fd72c0#n120
		//  * APKv1.0 compatibility - first non-hidden file is
		//  * considered to start the data section of the file.
		//  * This does not make any sense if the file has v2.0
		//  * style .PKGINFO
		if !startedDataSection && header.Name[0] == '.' && !strings.Contains(header.Name, "/") {
			continue
		}
		// whatever it is now, it is in the data section
		startedDataSection = true

		if err := a.fs.WriteHeader(header.Header, tfs, header.Offset, pkg); err != nil {
			return nil, err
		}

		files = append(files, header.Header)
	}

	return files, nil
}

func checksumFromHeader(header *tar.Header) ([]byte, error) {
	pax := header.PAXRecords
	if pax == nil {
		return nil, nil
	}

	hexsum, ok := pax[paxRecordsChecksumKey]
	if !ok {
		return nil, nil
	}

	if strings.HasPrefix(hexsum, "Q1") {
		// This is nonstandard but something we did at one point, handle it.
		// In other contexts, this Q1 prefix means "this is sha1 not md5".
		b64 := strings.TrimPrefix(hexsum, "Q1")

		checksum, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("decoding base64 checksum from header for %q: %w", header.Name, err)
		}

		return checksum, nil
	}

	checksum, err := hex.DecodeString(hexsum)
	if err != nil {
		return nil, fmt.Errorf("decoding hex checksum from header for %q: %w", header.Name, err)
	}

	return checksum, nil
}
