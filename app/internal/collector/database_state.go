package collector

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const DatabaseSnapshotStateSchema = "aegrail.collector.database_snapshot_state.v1"

type DatabaseSnapshotState struct {
	Schema    string                                `json:"schema"`
	UpdatedAt time.Time                             `json:"updated_at"`
	Database  string                                `json:"database"`
	Engine    string                                `json:"engine"`
	Profile   string                                `json:"profile"`
	Checks    map[string]DatabaseSnapshotCheckState `json:"checks"`
}

type DatabaseSnapshotCheckState struct {
	Name        string `json:"name"`
	Status      string `json:"status"`
	Metric      string `json:"metric,omitempty"`
	Table       string `json:"table,omitempty"`
	OptionName  string `json:"option_name,omitempty"`
	Count       int64  `json:"count,omitempty"`
	CountValid  bool   `json:"count_valid,omitempty"`
	ValueSHA256 string `json:"value_sha256,omitempty"`
	ValueBytes  int    `json:"value_bytes,omitempty"`
	Signature   string `json:"signature"`
}

type DatabaseSnapshotDiffResult struct {
	Baselined bool
	Skipped   bool
	Changes   []DatabaseSnapshotChange
}

type DatabaseSnapshotChange struct {
	Type     string
	Previous DatabaseSnapshotCheckState
	Current  DatabaseSnapshotCheckState
}

func UpdateDatabaseSnapshotState(path string, result DatabaseCollectResult) (DatabaseSnapshotDiffResult, error) {
	current := BuildDatabaseSnapshotState(result)
	if len(current.Checks) == 0 {
		return DatabaseSnapshotDiffResult{Skipped: true}, nil
	}

	previous, found, err := LoadDatabaseSnapshotState(path)
	if err != nil {
		return DatabaseSnapshotDiffResult{}, err
	}
	diff := DiffDatabaseSnapshotState(previous, found, current)
	if err := SaveDatabaseSnapshotState(path, current); err != nil {
		return DatabaseSnapshotDiffResult{}, err
	}
	return diff, nil
}

func BuildDatabaseSnapshotState(result DatabaseCollectResult) DatabaseSnapshotState {
	state := DatabaseSnapshotState{
		Schema:    DatabaseSnapshotStateSchema,
		UpdatedAt: result.FinishedAt,
		Database:  strings.TrimSpace(result.Name),
		Engine:    strings.TrimSpace(result.Engine),
		Profile:   strings.TrimSpace(result.Profile),
		Checks:    map[string]DatabaseSnapshotCheckState{},
	}
	if state.UpdatedAt.IsZero() {
		state.UpdatedAt = time.Now().UTC()
	}
	for _, check := range result.Checks {
		checkState, ok := databaseCheckState(check)
		if !ok {
			continue
		}
		state.Checks[checkState.Name] = checkState
	}
	return state
}

func LoadDatabaseSnapshotState(path string) (DatabaseSnapshotState, bool, error) {
	content, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return DatabaseSnapshotState{}, false, nil
	}
	if err != nil {
		return DatabaseSnapshotState{}, false, err
	}
	var state DatabaseSnapshotState
	if err := json.Unmarshal(content, &state); err != nil {
		return DatabaseSnapshotState{}, false, err
	}
	if state.Schema != DatabaseSnapshotStateSchema {
		return DatabaseSnapshotState{}, false, fmt.Errorf("unsupported database snapshot state schema %q", state.Schema)
	}
	if state.Checks == nil {
		state.Checks = map[string]DatabaseSnapshotCheckState{}
	}
	return state, true, nil
}

func SaveDatabaseSnapshotState(path string, state DatabaseSnapshotState) error {
	state.Schema = DatabaseSnapshotStateSchema
	if state.UpdatedAt.IsZero() {
		state.UpdatedAt = time.Now().UTC()
	}
	if state.Checks == nil {
		state.Checks = map[string]DatabaseSnapshotCheckState{}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	content, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(content, '\n'), 0o600)
}

func DiffDatabaseSnapshotState(previous DatabaseSnapshotState, found bool, current DatabaseSnapshotState) DatabaseSnapshotDiffResult {
	if !found {
		return DatabaseSnapshotDiffResult{Baselined: true}
	}
	diff := DatabaseSnapshotDiffResult{}
	names := make([]string, 0, len(current.Checks))
	for name := range current.Checks {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		currentCheck := current.Checks[name]
		previousCheck, ok := previous.Checks[name]
		if !ok {
			diff.Changes = append(diff.Changes, DatabaseSnapshotChange{
				Type:    "added",
				Current: currentCheck,
			})
			continue
		}
		if previousCheck.Signature != currentCheck.Signature {
			diff.Changes = append(diff.Changes, DatabaseSnapshotChange{
				Type:     "changed",
				Previous: previousCheck,
				Current:  currentCheck,
			})
		}
	}
	return diff
}

func databaseCheckState(check DatabaseCheckResult) (DatabaseSnapshotCheckState, bool) {
	state := DatabaseSnapshotCheckState{
		Name:        strings.TrimSpace(check.Name),
		Status:      strings.TrimSpace(check.Status),
		Metric:      strings.TrimSpace(check.Metric),
		Table:       strings.TrimSpace(check.Table),
		OptionName:  strings.TrimSpace(check.OptionName),
		Count:       check.Count,
		CountValid:  check.CountValid,
		ValueSHA256: strings.TrimSpace(check.ValueSHA256),
		ValueBytes:  check.ValueBytes,
	}
	if state.Name == "" {
		return DatabaseSnapshotCheckState{}, false
	}
	switch {
	case check.CountValid:
		state.Signature = fmt.Sprintf("count:%d", check.Count)
	case state.ValueSHA256 != "":
		state.Signature = fmt.Sprintf("sha256:%s:bytes:%d", state.ValueSHA256, state.ValueBytes)
	case state.Status == "missing":
		state.Signature = "missing"
	default:
		return DatabaseSnapshotCheckState{}, false
	}
	return state, true
}
