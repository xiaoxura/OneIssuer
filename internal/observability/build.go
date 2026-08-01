// Package observability provides build metadata, structured logging, and
// Prometheus metrics without relying on process-global registries.
package observability

import "runtime"

// BuildInfo is injected by the build and attached to process logs and metrics.
type BuildInfo struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildTime string `json:"build_time"`
	GoVersion string `json:"go_version"`
}

// NewBuildInfo normalizes linker-provided build values.
func NewBuildInfo(version, commit, buildTime string) BuildInfo {
	if version == "" {
		version = "development"
	}
	if commit == "" {
		commit = "unknown"
	}
	if buildTime == "" {
		buildTime = "unknown"
	}
	return BuildInfo{
		Version:   version,
		Commit:    commit,
		BuildTime: buildTime,
		GoVersion: runtime.Version(),
	}
}
