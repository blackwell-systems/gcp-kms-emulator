// Package buildinfo reports the emulator's version.
package buildinfo

import (
	"runtime/debug"
	"strings"
)

// Version returns the release version ("v0.10.2"), or "dev". stamped is the
// value set at build time with -ldflags "-X main.version=..." (the Docker
// images set it from the release tag). When it is empty, the module version
// recorded by `go install ...@vX.Y.Z` is used, and "dev" for local builds.
func Version(stamped string) string {
	if v := strings.TrimPrefix(stamped, "v"); v != "" {
		return "v" + v
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		if v := info.Main.Version; v != "" && v != "(devel)" {
			return "v" + strings.TrimPrefix(v, "v")
		}
	}
	return "dev"
}
