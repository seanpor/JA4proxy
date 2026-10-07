package tlsfixture

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type CorpusEntry struct {
	Name    string
	Raw     []byte
	WantJA4 string
}
// Corpus loads ClientHello binary fixtures from tests/fixtures/clienthello.
func Corpus(t testing.TB) []CorpusEntry {
	basePath := filepath.Join("tests", "fixtures", "clienthello")
	for i := 0; i < 5; i++ {
		if _, err := os.Stat(basePath); err == nil {
			break
		}
		basePath = filepath.Join("..", basePath)
	}

	knownFile := filepath.Join(basePath, "known_ja4.json")
	data, err := os.ReadFile(knownFile)
	if err != nil {
		t.Fatalf("Failed to read known_ja4.json: %v", err)
	}

	var known map[string]string
	if err := json.Unmarshal(data, &known); err != nil {
		t.Fatalf("Failed to unmarshal known_ja4.json: %v", err)
	}

	var entries []CorpusEntry
	for name, wantJA4 := range known {
		binPath := filepath.Join(basePath, name+".bin")
		raw, err := os.ReadFile(binPath)
		if err != nil {
			t.Fatalf("Failed to read binary fixture %s: %v", binPath, err)
		}
		entries = append(entries, CorpusEntry{
			Name:    name,
			Raw:     raw,
			WantJA4: wantJA4,
		})
	}
	return entries
}
