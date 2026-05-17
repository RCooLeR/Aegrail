package hub

import (
	"context"
	"strings"
	"time"
)

func (h *Hub) AllowRateLimit(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	if h == nil || h.rateLimiter == nil {
		return true, nil
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return false, nil
	}
	return h.rateLimiter.Allow(ctx, key, limit, window)
}
