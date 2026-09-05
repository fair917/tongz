package config

import (
	"os"
	"path/filepath"
	"testing"
)

// The shipped examples are the first thing anyone runs, so a rename that
// invalidates one should fail here rather than on their machine.
func TestShippedExamplesParse(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "..", "examples", "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	paths = append(paths, filepath.Join("..", "..", "tongz.example.yaml"))
	if len(paths) < 2 {
		t.Fatal("no example configurations found")
	}

	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("%s: %v", path, err)
			continue
		}
		if _, err := Parse(data); err != nil {
			t.Errorf("%s: %v", filepath.Base(path), err)
		}
	}
}
