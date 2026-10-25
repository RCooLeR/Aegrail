package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rcooler/aegrail/hub/internal/domain"
)

type TrafficRepository struct {
	pool *pgxpool.Pool
}

func NewTrafficRepository(pool *pgxpool.Pool) *TrafficRepository {
	return &TrafficRepository{pool: pool}
}

func (r *TrafficRepository) GetTrafficOverview(ctx context.Context, filter domain.TrafficFilter) (domain.TrafficOverview, error) {
	timelineStride, timelineBucket := trafficTimelineBucket(filter.Until.Sub(filter.Since))
	result := domain.TrafficOverview{
		Since:          filter.Since,
		Until:          filter.Until,
		StatusCodes:    []domain.TrafficStatusCount{},
		TopIPs:         []domain.TrafficIPSummary{},
		TopPaths:       []domain.TrafficPathSummary{},
		TopUserAgents:  []domain.TrafficUserAgentSummary{},
		Timeline:       []domain.TrafficTimelineBucket{},
		TimelineBucket: timelineBucket,
	}
	args := trafficFilterArgs(filter)
	const summaryQuery = `
		SELECT count(*), count(DISTINCT client_ip), coalesce(sum(response_bytes), 0),
			count(*) FILTER (WHERE status_code >= 400),
			count(*) FILTER (WHERE ua_is_bot)
		FROM hub_access_requests
		WHERE organization_id = $1 AND project_id = $2 AND environment_id = $3
			AND ($4::text = '' OR app_id = nullif($4::text, '')::uuid)
			AND event_time >= $5 AND event_time < $6
	`
	if err := r.pool.QueryRow(ctx, summaryQuery, args...).Scan(
		&result.TotalRequests,
		&result.UniqueIPs,
		&result.TotalBytes,
		&result.ErrorRequests,
		&result.BotRequests,
	); err != nil {
		return domain.TrafficOverview{}, err
	}

	statusCodes, err := r.listTrafficStatusCounts(ctx, filter, "", "")
	if err != nil {
		return domain.TrafficOverview{}, err
	}
	result.StatusCodes = statusCodes

	const ipsQuery = `
		WITH grouped AS (
			SELECT client_ip, count(*) AS requests,
				count(*) FILTER (WHERE status_code >= 400) AS error_requests,
				coalesce(sum(response_bytes), 0) AS total_bytes,
				min(event_time) AS first_seen, max(event_time) AS last_seen
			FROM hub_access_requests
			WHERE organization_id = $1 AND project_id = $2 AND environment_id = $3
				AND ($4::text = '' OR app_id = nullif($4::text, '')::uuid)
				AND event_time >= $5 AND event_time < $6 AND client_ip IS NOT NULL
			GROUP BY client_ip
			ORDER BY requests DESC, last_seen DESC
			LIMIT $7
		)
		SELECT host(grouped.client_ip), grouped.requests, grouped.error_requests,
			grouped.total_bytes, grouped.first_seen, grouped.last_seen,
			coalesce(policy.policy, 'neutral'),
			coalesce(intel.recognized_provider, ''),
			coalesce(intel.provider_verified AND intel.lookup_status = 'fresh' AND intel.expires_at > now(), false)
		FROM grouped
		LEFT JOIN hub_ip_manual_policies policy
			ON policy.organization_id = $1 AND policy.ip = grouped.client_ip
		LEFT JOIN hub_ip_intel intel
			ON intel.organization_id = $1 AND intel.ip = grouped.client_ip
		ORDER BY grouped.requests DESC, grouped.last_seen DESC
	`
	rows, err := r.pool.Query(ctx, ipsQuery, append(args, filter.Limit)...)
	if err != nil {
		return domain.TrafficOverview{}, err
	}
	for rows.Next() {
		var item domain.TrafficIPSummary
		if err := rows.Scan(
			&item.IP,
			&item.Requests,
			&item.ErrorRequests,
			&item.TotalBytes,
			&item.FirstSeen,
			&item.LastSeen,
			&item.ManualPolicy,
			&item.RecognizedProvider,
			&item.ProviderVerified,
		); err != nil {
			rows.Close()
			return domain.TrafficOverview{}, err
		}
		item.Trusted = item.ManualPolicy == "trusted"
		item.Blocked = item.ManualPolicy == "blocked"
		result.TopIPs = append(result.TopIPs, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return domain.TrafficOverview{}, err
	}
	rows.Close()

	paths, err := r.listTrafficPaths(ctx, filter, "", "")
	if err != nil {
		return domain.TrafficOverview{}, err
	}
	result.TopPaths = paths

	userAgents, err := r.listTrafficUserAgents(ctx, filter, "")
	if err != nil {
		return domain.TrafficOverview{}, err
	}
	result.TopUserAgents = userAgents

	const timelineQuery = `
		SELECT date_bin($7::interval, event_time, '1970-01-01 00:00:00+00'::timestamptz) AS bucket,
			count(*), count(*) FILTER (WHERE status_code >= 400),
			count(*) FILTER (WHERE ua_is_bot), coalesce(sum(response_bytes), 0)
		FROM hub_access_requests
		WHERE organization_id = $1 AND project_id = $2 AND environment_id = $3
			AND ($4::text = '' OR app_id = nullif($4::text, '')::uuid)
			AND event_time >= $5 AND event_time < $6
		GROUP BY bucket
		ORDER BY bucket
	`
	rows, err = r.pool.Query(ctx, timelineQuery, append(args, timelineStride)...)
	if err != nil {
		return domain.TrafficOverview{}, err
	}
	for rows.Next() {
		var item domain.TrafficTimelineBucket
		if err := rows.Scan(&item.Start, &item.Requests, &item.ErrorRequests, &item.BotRequests, &item.TotalBytes); err != nil {
			rows.Close()
			return domain.TrafficOverview{}, err
		}
		result.Timeline = append(result.Timeline, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return domain.TrafficOverview{}, err
	}
	rows.Close()
	return result, nil
}

// trafficTimelineBucket keeps charts detailed for short incident windows and
// bounded to roughly 30-72 points for longer operational views.
func trafficTimelineBucket(window time.Duration) (stride string, label string) {
	switch {
	case window <= time.Hour:
		return "1 minute", "minute"
	case window <= 6*time.Hour:
		return "5 minutes", "5 minutes"
	case window <= 24*time.Hour:
		return "30 minutes", "30 minutes"
	case window <= 3*24*time.Hour:
		return "1 hour", "hour"
	case window <= 14*24*time.Hour:
		return "6 hours", "6 hours"
	default:
		return "1 day", "day"
	}
}

func (r *TrafficRepository) GetTrafficIPDetail(ctx context.Context, filter domain.TrafficFilter, ip string) (domain.TrafficIPDetail, bool, error) {
	result := domain.TrafficIPDetail{
		IP:             ip,
		Since:          filter.Since,
		Until:          filter.Until,
		StatusCodes:    []domain.TrafficStatusCount{},
		TopPaths:       []domain.TrafficPathSummary{},
		UserAgents:     []domain.TrafficUserAgentSummary{},
		RecentRequests: []domain.TrafficRequestSample{},
	}
	args := append(trafficFilterArgs(filter), ip)
	const summaryQuery = `
		SELECT count(*), count(*) FILTER (WHERE status_code >= 400),
			coalesce(sum(response_bytes), 0), min(event_time), max(event_time)
		FROM hub_access_requests
		WHERE organization_id = $1 AND project_id = $2 AND environment_id = $3
			AND ($4::text = '' OR app_id = nullif($4::text, '')::uuid)
			AND event_time >= $5 AND event_time < $6 AND client_ip = $7::inet
	`
	var firstSeen *time.Time
	var lastSeen *time.Time
	if err := r.pool.QueryRow(ctx, summaryQuery, args...).Scan(
		&result.Requests,
		&result.ErrorRequests,
		&result.TotalBytes,
		&firstSeen,
		&lastSeen,
	); err != nil {
		return domain.TrafficIPDetail{}, false, err
	}
	if result.Requests == 0 {
		return result, false, nil
	}
	result.FirstSeen = firstSeen.UTC()
	result.LastSeen = lastSeen.UTC()

	statusCodes, err := r.listTrafficStatusCounts(ctx, filter, ip, "")
	if err != nil {
		return domain.TrafficIPDetail{}, false, err
	}
	result.StatusCodes = statusCodes
	paths, err := r.listTrafficPaths(ctx, filter, ip, "")
	if err != nil {
		return domain.TrafficIPDetail{}, false, err
	}
	result.TopPaths = paths
	userAgents, err := r.listTrafficUserAgents(ctx, filter, ip)
	if err != nil {
		return domain.TrafficIPDetail{}, false, err
	}
	result.UserAgents = userAgents

	const recentQuery = `
		SELECT event_id::text, event_time, coalesce(host(client_ip), ''), method, path,
			status_code, response_bytes, user_agent_hash, user_agent, ua_family
		FROM hub_access_requests
		WHERE organization_id = $1 AND project_id = $2 AND environment_id = $3
			AND ($4::text = '' OR app_id = nullif($4::text, '')::uuid)
			AND event_time >= $5 AND event_time < $6 AND client_ip = $7::inet
		ORDER BY event_time DESC, event_id DESC
		LIMIT $8
	`
	rows, err := r.pool.Query(ctx, recentQuery, append(args, filter.Limit)...)
	if err != nil {
		return domain.TrafficIPDetail{}, false, err
	}
	for rows.Next() {
		item, err := scanTrafficRequestSample(rows)
		if err != nil {
			rows.Close()
			return domain.TrafficIPDetail{}, false, err
		}
		result.RecentRequests = append(result.RecentRequests, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return domain.TrafficIPDetail{}, false, err
	}
	rows.Close()
	return result, true, nil
}

func (r *TrafficRepository) GetTrafficUserAgentDetail(ctx context.Context, filter domain.TrafficFilter, hash string) (domain.TrafficUserAgentDetail, bool, error) {
	result := domain.TrafficUserAgentDetail{
		Hash:           hash,
		Since:          filter.Since,
		Until:          filter.Until,
		StatusCodes:    []domain.TrafficStatusCount{},
		TopIPs:         []domain.TrafficIPSummary{},
		TopPaths:       []domain.TrafficPathSummary{},
		RecentRequests: []domain.TrafficRequestSample{},
	}
	args := append(trafficFilterArgs(filter), hash)
	const summaryQuery = `
		SELECT coalesce(max(user_agent), ''), coalesce(max(ua_family), ''),
			coalesce(max(ua_browser_family), ''), coalesce(max(ua_browser_version), ''),
			coalesce(max(ua_os_family), ''), coalesce(max(ua_os_version), ''),
			coalesce(max(ua_device_family), ''), coalesce(max(ua_actor_type), ''),
			coalesce(max(ua_known_actor), ''), coalesce(bool_or(ua_is_bot), false),
			coalesce(bool_or(ua_is_tool), false), coalesce(max(ua_risk_score), 0),
			count(*), count(DISTINCT client_ip),
			count(*) FILTER (WHERE status_code >= 400), min(event_time), max(event_time)
		FROM hub_access_requests
		WHERE organization_id = $1 AND project_id = $2 AND environment_id = $3
			AND ($4::text = '' OR app_id = nullif($4::text, '')::uuid)
			AND event_time >= $5 AND event_time < $6 AND user_agent_hash = $7
	`
	var firstSeen *time.Time
	var lastSeen *time.Time
	if err := r.pool.QueryRow(ctx, summaryQuery, args...).Scan(
		&result.UserAgent,
		&result.Family,
		&result.BrowserFamily,
		&result.BrowserVersion,
		&result.OSFamily,
		&result.OSVersion,
		&result.DeviceFamily,
		&result.ActorType,
		&result.KnownActor,
		&result.IsBot,
		&result.IsTool,
		&result.RiskScore,
		&result.Requests,
		&result.UniqueIPs,
		&result.ErrorRequests,
		&firstSeen,
		&lastSeen,
	); err != nil {
		return domain.TrafficUserAgentDetail{}, false, err
	}
	if result.Requests == 0 {
		return result, false, nil
	}
	result.FirstSeen = firstSeen.UTC()
	result.LastSeen = lastSeen.UTC()

	statusCodes, err := r.listTrafficStatusCounts(ctx, filter, "", hash)
	if err != nil {
		return domain.TrafficUserAgentDetail{}, false, err
	}
	result.StatusCodes = statusCodes
	paths, err := r.listTrafficPaths(ctx, filter, "", hash)
	if err != nil {
		return domain.TrafficUserAgentDetail{}, false, err
	}
	result.TopPaths = paths

	const ipsQuery = `
		WITH grouped AS (
			SELECT client_ip, count(*) AS requests,
				count(*) FILTER (WHERE status_code >= 400) AS error_requests,
				coalesce(sum(response_bytes), 0) AS total_bytes,
				min(event_time) AS first_seen, max(event_time) AS last_seen
			FROM hub_access_requests
			WHERE organization_id = $1 AND project_id = $2 AND environment_id = $3
				AND ($4::text = '' OR app_id = nullif($4::text, '')::uuid)
				AND event_time >= $5 AND event_time < $6
				AND user_agent_hash = $7 AND client_ip IS NOT NULL
			GROUP BY client_ip
			ORDER BY requests DESC, last_seen DESC
			LIMIT $8
		)
		SELECT host(grouped.client_ip), grouped.requests, grouped.error_requests,
			grouped.total_bytes, grouped.first_seen, grouped.last_seen,
			coalesce(policy.policy, 'neutral'), coalesce(intel.recognized_provider, ''),
			coalesce(intel.provider_verified AND intel.lookup_status = 'fresh' AND intel.expires_at > now(), false)
		FROM grouped
		LEFT JOIN hub_ip_manual_policies policy
			ON policy.organization_id = $1 AND policy.ip = grouped.client_ip
		LEFT JOIN hub_ip_intel intel
			ON intel.organization_id = $1 AND intel.ip = grouped.client_ip
		ORDER BY grouped.requests DESC, grouped.last_seen DESC
	`
	rows, err := r.pool.Query(ctx, ipsQuery, append(args, filter.Limit)...)
	if err != nil {
		return domain.TrafficUserAgentDetail{}, false, err
	}
	for rows.Next() {
		var item domain.TrafficIPSummary
		if err := rows.Scan(
			&item.IP,
			&item.Requests,
			&item.ErrorRequests,
			&item.TotalBytes,
			&item.FirstSeen,
			&item.LastSeen,
			&item.ManualPolicy,
			&item.RecognizedProvider,
			&item.ProviderVerified,
		); err != nil {
			rows.Close()
			return domain.TrafficUserAgentDetail{}, false, err
		}
		item.Trusted = item.ManualPolicy == "trusted"
		item.Blocked = item.ManualPolicy == "blocked"
		result.TopIPs = append(result.TopIPs, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return domain.TrafficUserAgentDetail{}, false, err
	}
	rows.Close()

	const recentQuery = `
		SELECT event_id::text, event_time, coalesce(host(client_ip), ''), method, path,
			status_code, response_bytes, user_agent_hash, user_agent, ua_family
		FROM hub_access_requests
		WHERE organization_id = $1 AND project_id = $2 AND environment_id = $3
			AND ($4::text = '' OR app_id = nullif($4::text, '')::uuid)
			AND event_time >= $5 AND event_time < $6 AND user_agent_hash = $7
		ORDER BY event_time DESC, event_id DESC
		LIMIT $8
	`
	rows, err = r.pool.Query(ctx, recentQuery, append(args, filter.Limit)...)
	if err != nil {
		return domain.TrafficUserAgentDetail{}, false, err
	}
	for rows.Next() {
		item, err := scanTrafficRequestSample(rows)
		if err != nil {
			rows.Close()
			return domain.TrafficUserAgentDetail{}, false, err
		}
		result.RecentRequests = append(result.RecentRequests, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return domain.TrafficUserAgentDetail{}, false, err
	}
	rows.Close()
	return result, true, nil
}

func (r *TrafficRepository) ListTrafficBots(ctx context.Context, filter domain.TrafficFilter) (domain.TrafficBotsPage, error) {
	result := domain.TrafficBotsPage{Bots: []domain.TrafficUserAgentSummary{}}
	const totalsQuery = `
		SELECT count(DISTINCT requests.user_agent_hash), count(*),
			count(*) FILTER (
				WHERE intel.provider_verified AND intel.lookup_status = 'fresh'
					AND intel.expires_at > now() AND intel.provider_family = requests.ua_family
			),
			count(*) FILTER (WHERE requests.status_code >= 400)
		FROM hub_access_requests requests
		LEFT JOIN hub_ip_intel intel
			ON intel.organization_id = requests.organization_id AND intel.ip = requests.client_ip
		WHERE requests.organization_id = $1 AND requests.project_id = $2
			AND requests.environment_id = $3
			AND ($4::text = '' OR requests.app_id = nullif($4::text, '')::uuid)
			AND requests.event_time >= $5 AND requests.event_time < $6
			AND (requests.ua_is_bot OR requests.ua_is_tool OR requests.ua_actor_type = 'malicious')
			AND requests.user_agent_hash <> ''
	`
	args := trafficFilterArgs(filter)
	if err := r.pool.QueryRow(ctx, totalsQuery, args...).Scan(
		&result.TotalClients,
		&result.TotalRequests,
		&result.TotalVerifiedRequests,
		&result.TotalErrorRequests,
	); err != nil {
		return domain.TrafficBotsPage{}, err
	}

	const query = `
		SELECT requests.user_agent_hash, max(requests.user_agent), max(requests.ua_family),
			max(requests.ua_browser_family), max(requests.ua_browser_version),
			max(requests.ua_os_family), max(requests.ua_os_version), max(requests.ua_device_family),
			max(requests.ua_actor_type), max(requests.ua_known_actor), bool_or(requests.ua_is_bot),
			bool_or(requests.ua_is_tool), max(requests.ua_risk_score), count(*),
			count(*) FILTER (
				WHERE intel.provider_verified AND intel.lookup_status = 'fresh'
					AND intel.expires_at > now() AND intel.provider_family = requests.ua_family
			),
			count(DISTINCT requests.client_ip),
			count(*) FILTER (WHERE requests.status_code >= 400),
			min(requests.event_time), max(requests.event_time)
		FROM hub_access_requests requests
		LEFT JOIN hub_ip_intel intel
			ON intel.organization_id = requests.organization_id AND intel.ip = requests.client_ip
		WHERE requests.organization_id = $1 AND requests.project_id = $2
			AND requests.environment_id = $3
			AND ($4::text = '' OR requests.app_id = nullif($4::text, '')::uuid)
			AND requests.event_time >= $5 AND requests.event_time < $6
			AND (requests.ua_is_bot OR requests.ua_is_tool OR requests.ua_actor_type = 'malicious')
			AND requests.user_agent_hash <> ''
		GROUP BY requests.user_agent_hash
		ORDER BY count(*) DESC, max(requests.event_time) DESC
		LIMIT $7
	`
	rows, err := r.pool.Query(ctx, query, append(args, filter.Limit)...)
	if err != nil {
		return domain.TrafficBotsPage{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var item domain.TrafficUserAgentSummary
		if err := rows.Scan(
			&item.Hash,
			&item.UserAgent,
			&item.Family,
			&item.BrowserFamily,
			&item.BrowserVersion,
			&item.OSFamily,
			&item.OSVersion,
			&item.DeviceFamily,
			&item.ActorType,
			&item.KnownActor,
			&item.IsBot,
			&item.IsTool,
			&item.RiskScore,
			&item.Requests,
			&item.VerifiedRequests,
			&item.UniqueIPs,
			&item.ErrorRequests,
			&item.FirstSeen,
			&item.LastSeen,
		); err != nil {
			return domain.TrafficBotsPage{}, err
		}
		result.Bots = append(result.Bots, item)
	}
	if err := rows.Err(); err != nil {
		return domain.TrafficBotsPage{}, err
	}
	return result, nil
}

func (r *TrafficRepository) GetTrafficIPIntel(ctx context.Context, organizationID domain.ID, ip string) (domain.TrafficIPIntel, bool, error) {
	const query = `
		SELECT host(ip), network_class, reverse_dns, dns_verified, provider_family,
			recognized_provider, provider_actor_type, provider_verified, lookup_status,
			last_lookup_at, expires_at, last_error
		FROM hub_ip_intel
		WHERE organization_id = $1 AND ip = $2::inet
	`
	var item domain.TrafficIPIntel
	err := r.pool.QueryRow(ctx, query, organizationID, ip).Scan(
		&item.IP,
		&item.NetworkClass,
		&item.ReverseDNS,
		&item.DNSVerified,
		&item.ProviderFamily,
		&item.RecognizedProvider,
		&item.ProviderActorType,
		&item.ProviderVerified,
		&item.LookupStatus,
		&item.LastLookupAt,
		&item.ExpiresAt,
		&item.LastError,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.TrafficIPIntel{}, false, nil
	}
	return item, err == nil, err
}

func (r *TrafficRepository) SaveTrafficIPIntel(ctx context.Context, organizationID domain.ID, intel domain.TrafficIPIntel) (domain.TrafficIPIntel, error) {
	const query = `
		INSERT INTO hub_ip_intel (
			organization_id, ip, network_class, reverse_dns, dns_verified,
			provider_family, recognized_provider, provider_actor_type,
			provider_verified, lookup_status, last_lookup_at, expires_at,
			last_error, created_at, updated_at
		)
		VALUES ($1, $2::inet, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, now(), now())
		ON CONFLICT (organization_id, ip) DO UPDATE SET
			network_class = EXCLUDED.network_class,
			reverse_dns = EXCLUDED.reverse_dns,
			dns_verified = EXCLUDED.dns_verified,
			provider_family = EXCLUDED.provider_family,
			recognized_provider = EXCLUDED.recognized_provider,
			provider_actor_type = EXCLUDED.provider_actor_type,
			provider_verified = EXCLUDED.provider_verified,
			lookup_status = EXCLUDED.lookup_status,
			last_lookup_at = EXCLUDED.last_lookup_at,
			expires_at = EXCLUDED.expires_at,
			last_error = EXCLUDED.last_error,
			updated_at = now()
		RETURNING host(ip), network_class, reverse_dns, dns_verified, provider_family,
			recognized_provider, provider_actor_type, provider_verified, lookup_status,
			last_lookup_at, expires_at, last_error
	`
	var saved domain.TrafficIPIntel
	err := r.pool.QueryRow(
		ctx,
		query,
		organizationID,
		intel.IP,
		intel.NetworkClass,
		intel.ReverseDNS,
		intel.DNSVerified,
		intel.ProviderFamily,
		intel.RecognizedProvider,
		intel.ProviderActorType,
		intel.ProviderVerified,
		intel.LookupStatus,
		intel.LastLookupAt,
		intel.ExpiresAt,
		intel.LastError,
	).Scan(
		&saved.IP,
		&saved.NetworkClass,
		&saved.ReverseDNS,
		&saved.DNSVerified,
		&saved.ProviderFamily,
		&saved.RecognizedProvider,
		&saved.ProviderActorType,
		&saved.ProviderVerified,
		&saved.LookupStatus,
		&saved.LastLookupAt,
		&saved.ExpiresAt,
		&saved.LastError,
	)
	return saved, err
}

func (r *TrafficRepository) GetTrafficIPPolicy(ctx context.Context, organizationID domain.ID, ip string) (domain.TrafficIPPolicy, bool, error) {
	const query = `
		SELECT host(ip), policy, reason, updated_by, created_at, updated_at
		FROM hub_ip_manual_policies
		WHERE organization_id = $1 AND ip = $2::inet
	`
	var item domain.TrafficIPPolicy
	err := r.pool.QueryRow(ctx, query, organizationID, ip).Scan(
		&item.IP,
		&item.Policy,
		&item.Reason,
		&item.UpdatedBy,
		&item.CreatedAt,
		&item.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.TrafficIPPolicy{}, false, nil
	}
	return item, err == nil, err
}

func (r *TrafficRepository) SaveTrafficIPPolicy(ctx context.Context, organizationID domain.ID, policy domain.TrafficIPPolicy) (domain.TrafficIPPolicy, error) {
	const query = `
		INSERT INTO hub_ip_manual_policies (
			organization_id, ip, policy, reason, updated_by, created_at, updated_at
		)
		VALUES ($1, $2::inet, $3, $4, $5, now(), now())
		ON CONFLICT (organization_id, ip) DO UPDATE SET
			policy = EXCLUDED.policy,
			reason = EXCLUDED.reason,
			updated_by = EXCLUDED.updated_by,
			updated_at = now()
		RETURNING host(ip), policy, reason, updated_by, created_at, updated_at
	`
	var saved domain.TrafficIPPolicy
	err := r.pool.QueryRow(ctx, query, organizationID, policy.IP, policy.Policy, policy.Reason, policy.UpdatedBy).Scan(
		&saved.IP,
		&saved.Policy,
		&saved.Reason,
		&saved.UpdatedBy,
		&saved.CreatedAt,
		&saved.UpdatedAt,
	)
	return saved, err
}

func (r *TrafficRepository) listTrafficStatusCounts(ctx context.Context, filter domain.TrafficFilter, ip string, userAgentHash string) ([]domain.TrafficStatusCount, error) {
	const query = `
		SELECT status_code, count(*)
		FROM hub_access_requests
		WHERE organization_id = $1 AND project_id = $2 AND environment_id = $3
			AND ($4::text = '' OR app_id = nullif($4::text, '')::uuid)
			AND event_time >= $5 AND event_time < $6 AND status_code IS NOT NULL
			AND ($7::text = '' OR client_ip = nullif($7::text, '')::inet)
			AND ($8::text = '' OR user_agent_hash = $8)
		GROUP BY status_code
		ORDER BY count(*) DESC, status_code
	`
	args := append(trafficFilterArgs(filter), ip, userAgentHash)
	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []domain.TrafficStatusCount{}
	for rows.Next() {
		var item domain.TrafficStatusCount
		if err := rows.Scan(&item.StatusCode, &item.Requests); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (r *TrafficRepository) listTrafficPaths(ctx context.Context, filter domain.TrafficFilter, ip string, userAgentHash string) ([]domain.TrafficPathSummary, error) {
	const query = `
		SELECT path, count(*), count(*) FILTER (WHERE status_code >= 400),
			coalesce(sum(response_bytes), 0), max(event_time)
		FROM hub_access_requests
		WHERE organization_id = $1 AND project_id = $2 AND environment_id = $3
			AND ($4::text = '' OR app_id = nullif($4::text, '')::uuid)
			AND event_time >= $5 AND event_time < $6 AND path <> ''
			AND ($7::text = '' OR client_ip = nullif($7::text, '')::inet)
			AND ($8::text = '' OR user_agent_hash = $8)
		GROUP BY path
		ORDER BY count(*) DESC, max(event_time) DESC
		LIMIT $9
	`
	args := append(trafficFilterArgs(filter), ip, userAgentHash, filter.Limit)
	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []domain.TrafficPathSummary{}
	for rows.Next() {
		var item domain.TrafficPathSummary
		if err := rows.Scan(&item.Path, &item.Requests, &item.ErrorRequests, &item.TotalBytes, &item.LastSeen); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (r *TrafficRepository) listTrafficUserAgents(ctx context.Context, filter domain.TrafficFilter, ip string) ([]domain.TrafficUserAgentSummary, error) {
	const query = `
		SELECT user_agent_hash, max(user_agent), max(ua_family), max(ua_browser_family),
			max(ua_browser_version), max(ua_os_family), max(ua_os_version),
			max(ua_device_family), max(ua_actor_type), max(ua_known_actor),
			bool_or(ua_is_bot), bool_or(ua_is_tool), max(ua_risk_score), count(*),
			count(DISTINCT client_ip), count(*) FILTER (WHERE status_code >= 400),
			min(event_time), max(event_time)
		FROM hub_access_requests
		WHERE organization_id = $1 AND project_id = $2 AND environment_id = $3
			AND ($4::text = '' OR app_id = nullif($4::text, '')::uuid)
			AND event_time >= $5 AND event_time < $6 AND user_agent_hash <> ''
			AND ($7::text = '' OR client_ip = nullif($7::text, '')::inet)
		GROUP BY user_agent_hash
		ORDER BY count(*) DESC, max(event_time) DESC
		LIMIT $8
	`
	args := append(trafficFilterArgs(filter), ip, filter.Limit)
	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []domain.TrafficUserAgentSummary{}
	for rows.Next() {
		var item domain.TrafficUserAgentSummary
		if err := rows.Scan(
			&item.Hash,
			&item.UserAgent,
			&item.Family,
			&item.BrowserFamily,
			&item.BrowserVersion,
			&item.OSFamily,
			&item.OSVersion,
			&item.DeviceFamily,
			&item.ActorType,
			&item.KnownActor,
			&item.IsBot,
			&item.IsTool,
			&item.RiskScore,
			&item.Requests,
			&item.UniqueIPs,
			&item.ErrorRequests,
			&item.FirstSeen,
			&item.LastSeen,
		); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

type trafficRequestScanner interface {
	Scan(dest ...any) error
}

func scanTrafficRequestSample(row trafficRequestScanner) (domain.TrafficRequestSample, error) {
	var item domain.TrafficRequestSample
	var statusCode *int
	var responseBytes *int64
	err := row.Scan(
		&item.EventID,
		&item.EventTime,
		&item.IP,
		&item.Method,
		&item.Path,
		&statusCode,
		&responseBytes,
		&item.UserAgentHash,
		&item.UserAgent,
		&item.UserAgentFamily,
	)
	if statusCode != nil {
		item.StatusCode = *statusCode
	}
	if responseBytes != nil {
		item.ResponseBytes = *responseBytes
	}
	return item, err
}

func trafficFilterArgs(filter domain.TrafficFilter) []any {
	return []any{
		filter.Scope.OrganizationID,
		filter.Scope.ProjectID,
		filter.Scope.EnvironmentID,
		string(filter.Scope.AppID),
		filter.Since.UTC(),
		filter.Until.UTC(),
	}
}
