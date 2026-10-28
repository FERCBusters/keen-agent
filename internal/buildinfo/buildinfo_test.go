package buildinfo

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestVersionMatchesRelease keeps every copy of the release version equal to
// VERSION, the one place a release changes it.
func TestVersionMatchesRelease(t *testing.T) {
	b, err := os.ReadFile("../../VERSION")
	if err != nil {
		t.Fatal(err)
	}
	release := strings.TrimSpace(string(b))
	if !regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(release) {
		t.Fatalf("VERSION %q is not MAJOR.MINOR.PATCH", release)
	}
	if Version != release {
		t.Fatalf("buildinfo.Version %q differs from VERSION %q", Version, release)
	}
	for _, path := range []string{"../../onboarding/package.json", "../../onboarding/package-lock.json"} {
		var pkg struct {
			Version  string `json:"version"`
			Packages map[string]struct {
				Version string `json:"version"`
			} `json:"packages"`
		}
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, &pkg); err != nil {
			t.Fatal(err)
		}
		if pkg.Version != release {
			t.Fatalf("%s version %q differs from VERSION %q", path, pkg.Version, release)
		}
		if root, ok := pkg.Packages[""]; ok && root.Version != release {
			t.Fatalf("%s root package version %q differs from VERSION %q", path, root.Version, release)
		}
	}
}
