package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"net/netip"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/rcooler/aegrail/hub/internal/domain"
	"github.com/rcooler/aegrail/hub/internal/useragent"
)

type trafficRequestProjection struct {
	Event              domain.IngestEvent
	ClientIP           any
	Method             string
	Scheme             string
	RequestHost        string
	Path               string
	QueryRedacted      string
	TargetRedacted     string
	Protocol           string
	StatusCode         any
	ResponseBytes      any
	RequestDurationMS  any
	UpstreamDurationMS any
	RefererRedacted    string
	UserAgent          string
	UserAgentHash      string
	Analysis           useragent.Analysis
	RemoteNetwork      string
	RemoteIsTor        bool
}

func projectTrafficRequests(ctx context.Context, tx pgx.Tx, events []domain.IngestEvent) error {
	const insertRequest = `
		INSERT INTO hub_access_requests (
			event_id, organization_id, project_id, environment_id, app_id,
			service_id, host_id, agent_id, event_time, event_type, client_ip,
			method, scheme, request_host, path, query_redacted,
			request_target_redacted, protocol, status_code, response_bytes,
			request_duration_ms, upstream_duration_ms, referer_redacted,
			user_agent, user_agent_hash, ua_family, ua_browser_family,
			ua_browser_version, ua_os_family, ua_os_version, ua_device_family,
			ua_actor_type, ua_known_actor, ua_is_bot, ua_is_tool, ua_risk_score,
			remote_network, remote_is_tor, created_at
		)
		VALUES (
			$1::uuid, $2::uuid, $3::uuid, $4::uuid, nullif($5::text, '')::uuid,
			nullif($6::text, '')::uuid, $7::uuid, $8::uuid, $9, $10, $11::inet,
			$12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23,
			$24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35,
			$36, $37, $38, $39
		)
		ON CONFLICT (event_id) DO NOTHING
	`

	batch := &pgx.Batch{}
	queued := 0
	for _, event := range events {
		projection, ok := buildTrafficRequestProjection(event)
		if !ok {
			continue
		}
		batch.Queue(
			insertRequest,
			projection.Event.ID,
			projection.Event.OrganizationID,
			projection.Event.ProjectID,
			projection.Event.EnvironmentID,
			string(projection.Event.AppID),
			string(projection.Event.ServiceID),
			projection.Event.HostID,
			projection.Event.AgentID,
			projection.Event.EventTime,
			projection.Event.EventType,
			projection.ClientIP,
			projection.Method,
			projection.Scheme,
			projection.RequestHost,
			projection.Path,
			projection.QueryRedacted,
			projection.TargetRedacted,
			projection.Protocol,
			projection.StatusCode,
			projection.ResponseBytes,
			projection.RequestDurationMS,
			projection.UpstreamDurationMS,
			projection.RefererRedacted,
			projection.UserAgent,
			projection.UserAgentHash,
			projection.Analysis.Family,
			projection.Analysis.BrowserFamily,
			projection.Analysis.BrowserVersion,
			projection.Analysis.OSFamily,
			projection.Analysis.OSVersion,
			projection.Analysis.DeviceFamily,
			projection.Analysis.ActorType,
			projection.Analysis.KnownActor,
			projection.Analysis.IsBot,
			projection.Analysis.IsTool,
			clampRiskScore(projection.Analysis.RiskScore),
			projection.RemoteNetwork,
			projection.RemoteIsTor,
			projection.Event.CreatedAt,
		)
		queued++
	}
	if queued == 0 {
		return nil
	}
	results := tx.SendBatch(ctx, batch)
	var insertErr error
	for index := 0; index < queued; index++ {
		if _, err := results.Exec(); err != nil && insertErr == nil {
			insertErr = fmt.Errorf("project traffic request %d: %w", index, err)
		}
	}
	if err := results.Close(); insertErr == nil && err != nil {
		insertErr = err
	}
	return insertErr
}

func buildTrafficRequestProjection(event domain.IngestEvent) (trafficRequestProjection, bool) {
	if event.EventType != "log.access" && event.EventType != "traffic.request" {
		return trafficRequestProjection{}, false
	}
	payload := event.Payload
	ua := strings.TrimSpace(payloadString(payload, "user_agent", ""))
	uaHash := ""
	if ua != "" {
		sum := sha256.Sum256([]byte(ua))
		uaHash = hex.EncodeToString(sum[:])
	}
	statusCode, statusCodePresent := payloadStrictInt64(payload, "status_code")
	responseBytes, responseBytesPresent := payloadStrictInt64(payload, "response_bytes")
	return trafficRequestProjection{
		Event:              event,
		ClientIP:           normalizedTrafficIP(payloadString(payload, "remote_addr", payloadString(payload, "client_ip", ""))),
		Method:             strings.ToUpper(strings.TrimSpace(payloadString(payload, "method", ""))),
		Scheme:             strings.ToLower(strings.TrimSpace(payloadString(payload, "scheme", ""))),
		RequestHost:        strings.TrimSpace(payloadString(payload, "request_host", payloadString(payload, "host", ""))),
		Path:               strings.TrimSpace(payloadString(payload, "path", "")),
		QueryRedacted:      strings.TrimSpace(payloadString(payload, "query_redacted", "")),
		TargetRedacted:     strings.TrimSpace(payloadString(payload, "request_target_redacted", "")),
		Protocol:           strings.TrimSpace(payloadString(payload, "protocol", "")),
		StatusCode:         nullableTrafficStatus(statusCode, statusCodePresent),
		ResponseBytes:      nullableNonNegativeInt(responseBytes, responseBytesPresent),
		RequestDurationMS:  trafficDurationMS(payload, "request_duration_ms", "request_time"),
		UpstreamDurationMS: trafficDurationMS(payload, "upstream_duration_ms", "upstream_response_time"),
		RefererRedacted:    strings.TrimSpace(payloadString(payload, "referer_redacted", "")),
		UserAgent:          ua,
		UserAgentHash:      uaHash,
		Analysis:           useragent.Analyze(ua, 1),
		RemoteNetwork:      strings.ToLower(strings.TrimSpace(payloadString(payload, "remote_network", ""))),
		RemoteIsTor:        payloadTruthy(payload, "remote_is_tor"),
	}, true
}

func normalizedTrafficIP(value string) any {
	value = strings.TrimSpace(value)
	if value == "" || value == "-" {
		return nil
	}
	if address, err := netip.ParseAddr(value); err == nil {
		return trafficInetString(address)
	}
	if prefix, err := netip.ParsePrefix(value); err == nil && prefix.Bits() == prefix.Addr().BitLen() {
		return trafficInetString(prefix.Addr())
	}
	if addressPort, err := netip.ParseAddrPort(value); err == nil {
		return trafficInetString(addressPort.Addr())
	}
	return nil
}

func trafficInetString(address netip.Addr) string {
	// PostgreSQL inet has no IPv6 scope-zone syntax. Zones are host-local
	// routing metadata, not part of the address, so strip them before binding.
	if address.Zone() != "" {
		address = address.WithZone("")
	}
	return address.Unmap().String()
}

func nullableTrafficStatus(value int64, present bool) any {
	if !present || value < 100 || value > 599 {
		return nil
	}
	return int(value)
}

func nullableNonNegativeInt(value int64, present bool) any {
	if !present || value < 0 {
		return nil
	}
	return value
}

func trafficDurationMS(payload map[string]any, millisKey string, secondsKey string) any {
	if value, ok := payloadFloat(payload, millisKey); ok && value >= 0 {
		return value
	}
	if value, ok := payloadFloat(payload, secondsKey); ok && value >= 0 {
		return value * 1000
	}
	return nil
}

func payloadFloat(payload map[string]any, key string) (float64, bool) {
	if payload == nil {
		return 0, false
	}
	value, ok := payload[key]
	if !ok || value == nil {
		return 0, false
	}
	var parsed float64
	switch typed := value.(type) {
	case float64:
		parsed = typed
	case float32:
		parsed = float64(typed)
	case int:
		parsed = float64(typed)
	case int64:
		parsed = float64(typed)
	case string:
		text := strings.TrimSpace(strings.Split(typed, ",")[0])
		if text == "" || text == "-" {
			return 0, false
		}
		var err error
		parsed, err = strconv.ParseFloat(text, 64)
		if err != nil {
			return 0, false
		}
	default:
		return 0, false
	}
	if math.IsNaN(parsed) || math.IsInf(parsed, 0) {
		return 0, false
	}
	return parsed, true
}

func payloadStrictInt64(payload map[string]any, key string) (int64, bool) {
	if payload == nil {
		return 0, false
	}
	value, ok := payload[key]
	if !ok || value == nil {
		return 0, false
	}
	switch typed := value.(type) {
	case int:
		return int64(typed), true
	case int8:
		return int64(typed), true
	case int16:
		return int64(typed), true
	case int32:
		return int64(typed), true
	case int64:
		return typed, true
	case uint:
		if uint64(typed) <= math.MaxInt64 {
			return int64(typed), true
		}
	case uint8:
		return int64(typed), true
	case uint16:
		return int64(typed), true
	case uint32:
		return int64(typed), true
	case uint64:
		if typed <= math.MaxInt64 {
			return int64(typed), true
		}
	case float32:
		value := float64(typed)
		if !math.IsNaN(value) && !math.IsInf(value, 0) && math.Trunc(value) == value && value >= math.MinInt64 && value <= math.MaxInt64 {
			return int64(value), true
		}
	case float64:
		if !math.IsNaN(typed) && !math.IsInf(typed, 0) && math.Trunc(typed) == typed && typed >= math.MinInt64 && typed <= math.MaxInt64 {
			return int64(typed), true
		}
	case string:
		parsed, err := strconv.ParseInt(strings.TrimSpace(typed), 10, 64)
		if err == nil {
			return parsed, true
		}
	case jsonNumber:
		parsed, err := typed.Int64()
		if err == nil {
			return parsed, true
		}
	}
	return 0, false
}

func payloadTruthy(payload map[string]any, key string) bool {
	if payload == nil {
		return false
	}
	switch value := payload[key].(type) {
	case bool:
		return value
	case string:
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "true", "1", "yes", "on":
			return true
		}
	case int:
		return value != 0
	case int64:
		return value != 0
	case float64:
		return value != 0
	}
	return false
}

func clampRiskScore(value int) int {
	if value < 0 {
		return 0
	}
	if value > 100 {
		return 100
	}
	return value
}
