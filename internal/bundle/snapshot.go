// Package bundle defines encrypted bundle runtime state. These structures are
// payloads of vault objects and must never be sent to the sync service in
// plaintext.
package bundle

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"time"
)

const SnapshotVersion = 1

var hexDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Snapshot struct {
	Version           int                     `json:"version"`
	Bundle            string                  `json:"bundle"`
	ManifestDigest    string                  `json:"manifest_digest"`
	PhysicalToLogical map[string]string       `json:"physical_to_logical"`
	Sources           map[string]SourceStatus `json:"sources"`
	RecordRevisions   map[string]int64        `json:"record_revisions"`
	CreatedAt         string                  `json:"created_at"`
}

type SourceStatus struct {
	Source      string `json:"source"`
	Status      string `json:"status"`
	Sensitivity string `json:"sensitivity,omitempty"`
}

func (snapshot Snapshot) Validate() error {
	if snapshot.Version != SnapshotVersion {
		return fmt.Errorf("unsupported bundle snapshot version %d", snapshot.Version)
	}
	if snapshot.Bundle == "" || !hexDigest.MatchString(snapshot.ManifestDigest) {
		return errors.New("bundle snapshot identity is invalid")
	}
	created, err := time.Parse(time.RFC3339, snapshot.CreatedAt)
	if err != nil || created.UTC().Format(time.RFC3339) != snapshot.CreatedAt {
		return errors.New("bundle snapshot creation time is invalid")
	}
	if snapshot.PhysicalToLogical == nil || snapshot.Sources == nil || snapshot.RecordRevisions == nil {
		return errors.New("bundle snapshot mappings are required")
	}
	logical := make(map[string]struct{}, len(snapshot.PhysicalToLogical))
	for physical, name := range snapshot.PhysicalToLogical {
		if physical == "" || name == "" {
			return errors.New("bundle snapshot record mapping is invalid")
		}
		if _, exists := logical[name]; exists {
			return fmt.Errorf("bundle snapshot logical record %s is duplicated", name)
		}
		logical[name] = struct{}{}
	}
	for name, status := range snapshot.Sources {
		if _, exists := logical[name]; !exists || status.Source == "" || status.Status == "" {
			return fmt.Errorf("bundle snapshot source %s is invalid", name)
		}
	}
	for name, revision := range snapshot.RecordRevisions {
		if _, exists := logical[name]; !exists || revision < 1 {
			return fmt.Errorf("bundle snapshot record revision %s is invalid", name)
		}
	}
	for name := range logical {
		if _, exists := snapshot.Sources[name]; !exists {
			return fmt.Errorf("bundle snapshot source %s is missing", name)
		}
		if _, exists := snapshot.RecordRevisions[name]; !exists {
			return fmt.Errorf("bundle snapshot record revision %s is missing", name)
		}
	}
	return nil
}

func (snapshot Snapshot) LogicalNames() []string {
	names := make([]string, 0, len(snapshot.PhysicalToLogical))
	for _, name := range snapshot.PhysicalToLogical {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
