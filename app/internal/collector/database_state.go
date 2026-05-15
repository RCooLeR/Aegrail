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
	Entities  map[string]DatabaseEntityState        `json:"entities,omitempty"`
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

type DatabaseEntityState struct {
	Type       string         `json:"type"`
	Key        string         `json:"key"`
	Label      string         `json:"label,omitempty"`
	Privileged bool           `json:"privileged,omitempty"`
	Attributes map[string]any `json:"attributes,omitempty"`
	Signature  string         `json:"signature"`
}

type DatabaseSnapshotDiffResult struct {
	Baselined     bool
	Skipped       bool
	Changes       []DatabaseSnapshotChange
	EntityChanges []DatabaseEntityChange
}

type DatabaseSnapshotChange struct {
	Type     string
	Previous DatabaseSnapshotCheckState
	Current  DatabaseSnapshotCheckState
}

type DatabaseEntityChange struct {
	Type     string
	Previous DatabaseEntityState
	Current  DatabaseEntityState
}

func UpdateDatabaseSnapshotState(path string, result DatabaseCollectResult) (DatabaseSnapshotDiffResult, error) {
	current := BuildDatabaseSnapshotState(result)
	if len(current.Checks) == 0 && len(current.Entities) == 0 {
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
		Entities:  map[string]DatabaseEntityState{},
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
	for _, entity := range result.Entities {
		entityState, ok := databaseEntityState(entity)
		if !ok {
			continue
		}
		state.Entities[entityState.Key] = entityState
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
	if state.Entities == nil {
		state.Entities = map[string]DatabaseEntityState{}
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
	if state.Entities == nil {
		state.Entities = map[string]DatabaseEntityState{}
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
	entityKeys := make([]string, 0, len(current.Entities))
	for key := range current.Entities {
		entityKeys = append(entityKeys, key)
	}
	sort.Strings(entityKeys)
	for _, key := range entityKeys {
		currentEntity := current.Entities[key]
		previousEntity, ok := previous.Entities[key]
		if !ok {
			diff.EntityChanges = append(diff.EntityChanges, DatabaseEntityChange{
				Type:    "added",
				Current: currentEntity,
			})
			continue
		}
		if previousEntity.Signature != currentEntity.Signature {
			if databaseEntityEquivalentForDiff(previousEntity, currentEntity) {
				continue
			}
			diff.EntityChanges = append(diff.EntityChanges, DatabaseEntityChange{
				Type:     "changed",
				Previous: previousEntity,
				Current:  currentEntity,
			})
		}
	}
	previousEntityKeys := make([]string, 0, len(previous.Entities))
	for key := range previous.Entities {
		previousEntityKeys = append(previousEntityKeys, key)
	}
	sort.Strings(previousEntityKeys)
	for _, key := range previousEntityKeys {
		if _, ok := current.Entities[key]; ok {
			continue
		}
		diff.EntityChanges = append(diff.EntityChanges, DatabaseEntityChange{
			Type:     "removed",
			Previous: previous.Entities[key],
		})
	}
	return diff
}

func databaseEntityEquivalentForDiff(previous DatabaseEntityState, current DatabaseEntityState) bool {
	if previous.Type != current.Type || previous.Key != current.Key || previous.Privileged != current.Privileged {
		return false
	}
	if !isDatabasePIIAccountEntity(current.Type) {
		return false
	}
	previousAttributes := databaseEntityComparableAttributes(previous.Attributes)
	currentAttributes := databaseEntityComparableAttributes(current.Attributes)
	if len(previousAttributes) != len(currentAttributes) {
		return false
	}
	for key, previousValue := range previousAttributes {
		if fmt.Sprint(previousValue) != fmt.Sprint(currentAttributes[key]) {
			return false
		}
	}
	return true
}

func isDatabasePIIAccountEntity(entityType string) bool {
	switch strings.TrimSpace(entityType) {
	case "wordpress_user", "prestashop_employee":
		return true
	default:
		return false
	}
}

func databaseEntityComparableAttributes(attributes map[string]any) map[string]any {
	comparable := map[string]any{}
	for key, value := range attributes {
		key = strings.TrimSpace(key)
		if key == "" || isDatabasePIIEvidenceAttribute(key) {
			continue
		}
		comparable[key] = value
	}
	return comparable
}

func isDatabasePIIEvidenceAttribute(key string) bool {
	switch strings.TrimSpace(key) {
	case "account_display",
		"email",
		"login",
		"email_masked",
		"login_masked",
		"email_sha256",
		"login_sha256",
		"email_hmac_sha256",
		"login_hmac_sha256":
		return true
	default:
		return false
	}
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

func databaseEntityState(entity DatabaseEntityObservation) (DatabaseEntityState, bool) {
	state := DatabaseEntityState{
		Type:       strings.TrimSpace(entity.Type),
		Key:        strings.TrimSpace(entity.Key),
		Label:      strings.TrimSpace(entity.Label),
		Privileged: entity.Privileged,
		Attributes: cloneAnyMap(entity.Attributes),
		Signature:  strings.TrimSpace(entity.Signature),
	}
	if state.Type == "" || state.Key == "" {
		return DatabaseEntityState{}, false
	}
	if state.Signature == "" {
		state.Signature = databaseEntitySignature(DatabaseEntityObservation{
			Type:       state.Type,
			Key:        state.Key,
			Label:      state.Label,
			Privileged: state.Privileged,
			Attributes: state.Attributes,
		})
	}
	return state, true
}

func cloneAnyMap(values map[string]any) map[string]any {
	if len(values) == 0 {
		return nil
	}
	clone := make(map[string]any, len(values))
	for key, value := range values {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		clone[key] = value
	}
	return clone
}
