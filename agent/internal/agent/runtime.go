package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/rcooler/aegrail/agent/internal/domain"
	"github.com/rcooler/aegrail/agent/internal/fsutil"
	"github.com/rcooler/aegrail/agent/internal/wire"
)

const (
	ConfigSchema = "aegrail.agent.config.v1"
	QueueSchema  = "aegrail.agent.queue.v1"
)

type Runtime struct {
	Config       Config
	client       *http.Client
	now          func() time.Time
	torExitCache torExitRuntimeCache
}

type Config struct {
	ConfigPath    string
	QueueDir      string
	SentRetention time.Duration
	Identity      *Identity
}

type Identity struct {
	Schema        string            `json:"schema"`
	HubURL        string            `json:"hub_url"`
	HubProtocol   string            `json:"hub_protocol,omitempty"`
	HubPublicKey  string            `json:"hub_public_key,omitempty"`
	NodeSecret    string            `json:"node_secret,omitempty"`
	NodeSecretEnv string            `json:"node_secret_env,omitempty"`
	QueueDir      string            `json:"queue_dir"`
	Org           string            `json:"org"`
	Project       string            `json:"project"`
	Environment   string            `json:"environment"`
	App           string            `json:"app,omitempty"`
	Service       string            `json:"service,omitempty"`
	Host          string            `json:"host"`
	AgentID       string            `json:"agent_id"`
	Region        string            `json:"region,omitempty"`
	Labels        map[string]string `json:"labels,omitempty"`
	InstalledAt   time.Time         `json:"installed_at"`
}

func (i Identity) UsesWireProtocol() bool {
	return strings.TrimSpace(i.HubProtocol) == "" || strings.TrimSpace(i.HubProtocol) == "aegrail-wire-v1"
}

type EnqueueEventInput struct {
	BatchID   string
	EventTime time.Time
	App       string
	Service   string
	Type      string
	Target    string
	Severity  string
	Message   string
	Region    string
	Labels    map[string]string
	Payload   map[string]any
}

type EnqueueEventsInput struct {
	BatchID string
	App     string
	Service string
	Source  string
	Region  string
	Labels  map[string]string
	Events  []EnqueueEventInput
}

type QueuedBatch struct {
	Schema      string            `json:"schema"`
	QueuedAt    time.Time         `json:"queued_at"`
	Org         string            `json:"org"`
	Project     string            `json:"project"`
	Environment string            `json:"environment"`
	App         string            `json:"app,omitempty"`
	Service     string            `json:"service,omitempty"`
	Host        string            `json:"host"`
	AgentID     string            `json:"agent_id"`
	BatchID     string            `json:"batch_id"`
	Source      string            `json:"source"`
	Region      string            `json:"region,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Events      []QueuedEvent     `json:"events"`
}

type QueuedEvent struct {
	Time     time.Time         `json:"time"`
	Type     string            `json:"type"`
	Target   string            `json:"target,omitempty"`
	Severity string            `json:"severity,omitempty"`
	Message  string            `json:"message,omitempty"`
	Region   string            `json:"region,omitempty"`
	Labels   map[string]string `json:"labels,omitempty"`
	Payload  map[string]any    `json:"payload,omitempty"`
}

type QueueStatus struct {
	ConfigPath string
	QueueDir   string
	Installed  bool
	Pending    int
	Sent       int
	Failed     int
	Discarded  int
}

type SendResult struct {
	PendingBefore int
	Sent          int
	Failed        int
	PendingAfter  int
	Errors        []string
}

type DiscardPendingResult struct {
	PendingBefore int
	Discarded     int
	PendingAfter  int
	DiscardDir    string
	Errors        []string
}

func NewRuntime(config Config) *Runtime {
	if config.Identity != nil && strings.TrimSpace(config.Identity.QueueDir) != "" {
		config.QueueDir = config.Identity.QueueDir
	}
	if strings.TrimSpace(config.ConfigPath) == "" {
		config.ConfigPath = ".aegrail/agent.json"
	}
	if strings.TrimSpace(config.QueueDir) == "" {
		config.QueueDir = ".aegrail/queue"
	}
	return &Runtime{
		Config: config,
		client: &http.Client{Timeout: 10 * time.Second},
		now:    time.Now,
	}
}

func (r *Runtime) Install(_ context.Context, identity Identity) (Identity, error) {
	identity.Schema = ConfigSchema
	identity.HubURL = strings.TrimSpace(identity.HubURL)
	identity.HubProtocol = strings.TrimSpace(identity.HubProtocol)
	identity.HubPublicKey = strings.TrimSpace(identity.HubPublicKey)
	identity.NodeSecret = strings.TrimSpace(identity.NodeSecret)
	identity.NodeSecretEnv = strings.TrimSpace(identity.NodeSecretEnv)
	identity.QueueDir = strings.TrimSpace(identity.QueueDir)
	if identity.QueueDir == "" {
		identity.QueueDir = r.Config.QueueDir
	}
	identity.Org = strings.TrimSpace(identity.Org)
	identity.Project = strings.TrimSpace(identity.Project)
	identity.Environment = strings.TrimSpace(identity.Environment)
	identity.App = strings.TrimSpace(identity.App)
	identity.Service = strings.TrimSpace(identity.Service)
	identity.Host = strings.TrimSpace(identity.Host)
	identity.AgentID = strings.TrimSpace(identity.AgentID)
	identity.Region = strings.TrimSpace(identity.Region)
	identity.Labels = cloneStringMap(identity.Labels)
	identity.InstalledAt = r.now().UTC()
	if err := validateIdentity(identity); err != nil {
		return Identity{}, err
	}
	if err := ensureQueueDirs(identity.QueueDir); err != nil {
		return Identity{}, err
	}
	if err := os.MkdirAll(filepath.Dir(r.Config.ConfigPath), 0o700); err != nil {
		return Identity{}, err
	}
	content, err := json.MarshalIndent(identity, "", "  ")
	if err != nil {
		return Identity{}, err
	}
	if err := fsutil.WriteFileAtomicSync(r.Config.ConfigPath, append(content, '\n'), 0o600); err != nil {
		return Identity{}, err
	}
	return identity, nil
}

func (r *Runtime) LoadIdentity(_ context.Context) (Identity, error) {
	if r.Config.Identity != nil {
		identity := *r.Config.Identity
		identity.Labels = cloneStringMap(identity.Labels)
		if strings.TrimSpace(identity.QueueDir) == "" {
			identity.QueueDir = r.Config.QueueDir
		}
		if err := validateIdentity(identity); err != nil {
			return Identity{}, err
		}
		return identity, nil
	}
	content, err := os.ReadFile(r.Config.ConfigPath)
	if err != nil {
		return Identity{}, err
	}
	var identity Identity
	if err := json.Unmarshal(content, &identity); err != nil {
		return Identity{}, err
	}
	if strings.TrimSpace(identity.QueueDir) == "" {
		identity.QueueDir = r.Config.QueueDir
	}
	if err := validateIdentity(identity); err != nil {
		return Identity{}, err
	}
	return identity, nil
}

func (r *Runtime) Status(ctx context.Context) (QueueStatus, error) {
	status := QueueStatus{
		ConfigPath: r.Config.ConfigPath,
		QueueDir:   r.Config.QueueDir,
	}
	identity, err := r.LoadIdentity(ctx)
	if err == nil {
		status.Installed = true
		status.QueueDir = identity.QueueDir
	} else if !errors.Is(err, os.ErrNotExist) {
		return QueueStatus{}, err
	}
	status.Pending = countQueueFiles(filepath.Join(status.QueueDir, "pending"))
	status.Sent = countQueueFiles(filepath.Join(status.QueueDir, "sent"))
	status.Failed = countQueueFiles(filepath.Join(status.QueueDir, "failed"))
	status.Discarded = countQueueFiles(filepath.Join(status.QueueDir, "discarded"))
	return status, nil
}

func (r *Runtime) EnqueueEvent(ctx context.Context, input EnqueueEventInput) (QueuedBatch, string, error) {
	return r.EnqueueEvents(ctx, EnqueueEventsInput{
		BatchID: input.BatchID,
		App:     input.App,
		Service: input.Service,
		Region:  input.Region,
		Labels:  input.Labels,
		Events:  []EnqueueEventInput{input},
	})
}

func (r *Runtime) EnqueueEvents(ctx context.Context, input EnqueueEventsInput) (QueuedBatch, string, error) {
	identity, err := r.LoadIdentity(ctx)
	if err != nil {
		return QueuedBatch{}, "", err
	}
	if err := ensureQueueDirs(identity.QueueDir); err != nil {
		return QueuedBatch{}, "", err
	}
	batchID := strings.TrimSpace(input.BatchID)
	if batchID == "" {
		batchID = newBatchID(r.now)
	}
	region := strings.TrimSpace(input.Region)
	if region == "" {
		region = identity.Region
	}
	app := strings.TrimSpace(input.App)
	if app == "" {
		app = identity.App
	}
	service := strings.TrimSpace(input.Service)
	if service == "" {
		service = identity.Service
	}
	labels := cloneStringMap(identity.Labels)
	for key, value := range input.Labels {
		key = strings.TrimSpace(key)
		if key != "" {
			labels[key] = strings.TrimSpace(value)
		}
	}
	if len(input.Events) == 0 {
		return QueuedBatch{}, "", errors.New("at least one event is required")
	}
	source := strings.TrimSpace(input.Source)
	if source == "" {
		source = "agent-queue"
	}
	events := make([]QueuedEvent, 0, len(input.Events))
	for _, eventInput := range input.Events {
		eventType := strings.TrimSpace(eventInput.Type)
		if eventType == "" {
			return QueuedBatch{}, "", errors.New("event type is required")
		}
		severity := strings.TrimSpace(eventInput.Severity)
		if severity == "" {
			severity = string(domain.SeverityInfo)
		}
		eventTime := eventInput.EventTime
		if eventTime.IsZero() {
			eventTime = r.now().UTC()
		}
		payload := eventInput.Payload
		if payload == nil {
			payload = map[string]any{}
		}
		events = append(events, QueuedEvent{
			Time:     eventTime.UTC(),
			Type:     eventType,
			Target:   strings.TrimSpace(eventInput.Target),
			Severity: severity,
			Message:  strings.TrimSpace(eventInput.Message),
			Region:   region,
			Labels:   cloneStringMap(eventInput.Labels),
			Payload:  payload,
		})
	}
	batch := QueuedBatch{
		Schema:      QueueSchema,
		QueuedAt:    r.now().UTC(),
		Org:         identity.Org,
		Project:     identity.Project,
		Environment: identity.Environment,
		App:         app,
		Service:     service,
		Host:        identity.Host,
		AgentID:     identity.AgentID,
		BatchID:     batchID,
		Source:      source,
		Region:      region,
		Labels:      labels,
		Events:      events,
	}
	content, err := json.MarshalIndent(batch, "", "  ")
	if err != nil {
		return QueuedBatch{}, "", err
	}
	path := filepath.Join(identity.QueueDir, "pending", safeFilename(batchID)+".json")
	if _, err := os.Stat(path); err == nil {
		return batch, path, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return QueuedBatch{}, "", err
	}
	if err := fsutil.WriteFileAtomicSync(path, append(content, '\n'), 0o600); err != nil {
		if errors.Is(err, os.ErrExist) {
			return batch, path, nil
		}
		return QueuedBatch{}, "", err
	}
	return batch, path, nil
}

func (r *Runtime) SendQueued(ctx context.Context, limit int) (SendResult, error) {
	identity, err := r.LoadIdentity(ctx)
	if err != nil {
		return SendResult{}, err
	}
	if strings.TrimSpace(identity.HubPublicKey) == "" {
		return SendResult{}, errors.New("hub public key is required")
	}
	nodeSecret := identity.ResolvedNodeSecret()
	if strings.TrimSpace(nodeSecret) == "" {
		return SendResult{}, errors.New("node secret is required")
	}
	pendingDir := filepath.Join(identity.QueueDir, "pending")
	sentDir := filepath.Join(identity.QueueDir, "sent")
	if err := ensureQueueDirs(identity.QueueDir); err != nil {
		return SendResult{}, err
	}
	files, err := queueFiles(pendingDir)
	if err != nil {
		return SendResult{}, err
	}
	if limit > 0 && limit < len(files) {
		files = files[:limit]
	}
	result := SendResult{PendingBefore: len(files)}
	for _, path := range files {
		content, err := os.ReadFile(path)
		if err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", filepath.Base(path), err))
			continue
		}
		if err := r.sendBatch(ctx, identity, nodeSecret, content); err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", filepath.Base(path), err))
			continue
		}
		if err := r.archiveOrDeleteSentBatch(path, sentDir); err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", filepath.Base(path), err))
			continue
		}
		result.Sent++
	}
	status, err := r.Status(ctx)
	if err != nil {
		return result, err
	}
	result.PendingAfter = status.Pending
	return result, nil
}

func (r *Runtime) archiveOrDeleteSentBatch(path string, sentDir string) error {
	if r.Config.SentRetention <= 0 {
		return os.Remove(path)
	}
	destination := filepath.Join(sentDir, filepath.Base(path))
	if err := os.Rename(path, uniquePath(destination)); err != nil {
		return err
	}
	return cleanupQueueDir(sentDir, r.Config.SentRetention, r.now())
}

func (r *Runtime) DiscardPending(ctx context.Context, limit int) (DiscardPendingResult, error) {
	identity, err := r.LoadIdentity(ctx)
	if err != nil {
		return DiscardPendingResult{}, err
	}
	if err := ensureQueueDirs(identity.QueueDir); err != nil {
		return DiscardPendingResult{}, err
	}
	pendingDir := filepath.Join(identity.QueueDir, "pending")
	discardedDir := filepath.Join(identity.QueueDir, "discarded")
	files, err := queueFiles(pendingDir)
	if err != nil {
		return DiscardPendingResult{}, err
	}
	if limit > 0 && limit < len(files) {
		files = files[:limit]
	}
	result := DiscardPendingResult{
		PendingBefore: len(files),
		DiscardDir:    discardedDir,
	}
	for _, path := range files {
		destination := filepath.Join(discardedDir, filepath.Base(path))
		if err := os.Rename(path, uniquePath(destination)); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", filepath.Base(path), err))
			continue
		}
		result.Discarded++
	}
	status, err := r.Status(ctx)
	if err != nil {
		return result, err
	}
	result.PendingAfter = status.Pending
	return result, nil
}

func (r *Runtime) sendBatch(ctx context.Context, identity Identity, nodeSecret string, body []byte) error {
	endpoint := strings.TrimRight(strings.TrimSpace(identity.HubURL), "/") + "/api/v1/ingest/events"
	envelope, err := wire.Encrypt(body, identity.AgentID, nodeSecret, identity.HubPublicKey, r.now())
	if err != nil {
		return err
	}
	requestBody, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(requestBody))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := r.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return fmt.Errorf("Hub returned %s: %s", response.Status, strings.TrimSpace(string(body)))
	}
	return nil
}

func (identity Identity) ResolvedNodeSecret() string {
	if strings.TrimSpace(identity.NodeSecret) != "" {
		return strings.TrimSpace(identity.NodeSecret)
	}
	if strings.TrimSpace(identity.NodeSecretEnv) == "" {
		return ""
	}
	return strings.TrimSpace(os.Getenv(identity.NodeSecretEnv))
}

func validateIdentity(identity Identity) error {
	switch {
	case identity.HubURL == "":
		return errors.New("hub url is required")
	case strings.TrimSpace(identity.HubProtocol) != "" && strings.TrimSpace(identity.HubProtocol) != "aegrail-wire-v1":
		return errors.New("hub protocol must be aegrail-wire-v1")
	case identity.Org == "":
		return errors.New("organization is required")
	case identity.Project == "":
		return errors.New("project is required")
	case identity.Environment == "":
		return errors.New("environment is required")
	case identity.Host == "":
		return errors.New("host is required")
	case identity.AgentID == "":
		return errors.New("agent id is required")
	}
	return nil
}

func ensureQueueDirs(queueDir string) error {
	for _, name := range []string{"pending", "sent", "failed", "discarded"} {
		if err := os.MkdirAll(filepath.Join(queueDir, name), 0o700); err != nil {
			return err
		}
	}
	return nil
}

func countQueueFiles(dir string) int {
	files, err := queueFiles(dir)
	if err != nil {
		return 0
	}
	return len(files)
}

func queueFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
			files = append(files, filepath.Join(dir, entry.Name()))
		}
	}
	sort.Strings(files)
	return files, nil
}

func cleanupQueueDir(dir string, retention time.Duration, now time.Time) error {
	if retention <= 0 {
		return nil
	}
	files, err := queueFiles(dir)
	if err != nil {
		return err
	}
	cutoff := now.UTC().Add(-retention)
	var errs []string
	for _, path := range files {
		info, err := os.Stat(path)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, fmt.Sprintf("%s: %v", filepath.Base(path), err))
			}
			continue
		}
		if info.ModTime().After(cutoff) {
			continue
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Sprintf("%s: %v", filepath.Base(path), err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("cleanup queue dir %s: %s", dir, strings.Join(errs, "; "))
	}
	return nil
}

func newBatchID(now func() time.Time) string {
	return now().UTC().Format("20060102T150405Z") + "-" + randomHex(8)
}

func randomHex(bytesLen int) string {
	bytes := make([]byte, bytesLen)
	if _, err := rand.Read(bytes); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(bytes)
}

func safeFilename(value string) string {
	var builder strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			builder.WriteRune(r)
			continue
		}
		builder.WriteByte('_')
	}
	if builder.Len() == 0 {
		return randomHex(8)
	}
	return builder.String()
}

func uniquePath(path string) string {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return path
	}
	ext := filepath.Ext(path)
	base := strings.TrimSuffix(path, ext)
	return fmt.Sprintf("%s-%s%s", base, randomHex(4), ext)
}

func cloneStringMap(values map[string]string) map[string]string {
	clone := make(map[string]string, len(values))
	for key, value := range values {
		key = strings.TrimSpace(key)
		if key != "" {
			clone[key] = strings.TrimSpace(value)
		}
	}
	return clone
}

func mergeStringMaps(base map[string]string, overlays ...map[string]string) map[string]string {
	merged := cloneStringMap(base)
	for _, overlay := range overlays {
		for key, value := range overlay {
			key = strings.TrimSpace(key)
			if key != "" {
				merged[key] = strings.TrimSpace(value)
			}
		}
	}
	return merged
}
