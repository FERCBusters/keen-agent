// Package buildinfo holds the release version shared by every binary.
//
// VERSION at the repository root is the single source of the release
// version. Packaging scripts read that file; this constant must match it, and
// TestVersionMatchesRelease fails the build when they differ.
package buildinfo

// Version is the release version of keen-agent, keen-posture and the setup
// helper.
const Version = "0.2.2"
