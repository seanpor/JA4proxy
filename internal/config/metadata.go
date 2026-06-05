package config

var (
	// Version is the combined major.minor.build version string.
	// Injected via ldflags.
	Version = "2.0.0-dev"

	// BuildDate is the RFC3339 timestamp of the build.
	// Injected via ldflags.
	BuildDate = "unknown"

	// GitCommit is the HEAD SHA at build time.
	// Injected via ldflags.
	GitCommit = "unknown"
)
