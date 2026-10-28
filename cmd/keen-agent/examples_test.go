package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestExamplesAreValidConfiguration keeps the shipped examples loadable.
func TestExamplesAreValidConfiguration(t *testing.T) {
	for _, name := range []string{"config.yaml", "autoscale.yaml", "posture.yaml"} {
		b, err := os.ReadFile(filepath.Join("..", "..", "examples", name))
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), name)
		if err = os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err = config(path); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}
