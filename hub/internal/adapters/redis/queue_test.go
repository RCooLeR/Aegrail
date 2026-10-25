package redis

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"
)

func TestParseClientOptionsUsesRESP3AndIdentifiesHub(t *testing.T) {
	options, err := parseClientOptions("redis://localhost:6379/0")
	if err != nil {
		t.Fatalf("parseClientOptions returned error: %v", err)
	}
	if options.Protocol != 3 {
		t.Fatalf("protocol = %d, want RESP3", options.Protocol)
	}
	if options.ClientName != "aegrail-hub" {
		t.Fatalf("client name = %q, want aegrail-hub", options.ClientName)
	}
}

func TestParseClientOptionsPreservesURLOverrides(t *testing.T) {
	options, err := parseClientOptions("redis://localhost:6379/0?protocol=2&client_name=custom-worker")
	if err != nil {
		t.Fatalf("parseClientOptions returned error: %v", err)
	}
	if options.Protocol != 2 {
		t.Fatalf("protocol = %d, want RESP2 override", options.Protocol)
	}
	if options.ClientName != "custom-worker" {
		t.Fatalf("client name = %q, want custom-worker", options.ClientName)
	}
}

func TestClientRedis8Integration(t *testing.T) {
	redisURL := strings.TrimSpace(os.Getenv("AEGRAIL_TEST_REDIS_URL"))
	if redisURL == "" {
		t.Skip("set AEGRAIL_TEST_REDIS_URL to run Redis adapter integration tests")
	}

	ctx := context.Background()
	prefix := "aegrail-test-" + randomRedisHex(t, 8)
	client, err := NewClient(ctx, Config{URL: redisURL, KeyPrefix: prefix})
	if err != nil {
		t.Fatalf("NewClient returned error: %v", err)
	}
	t.Cleanup(func() {
		keys, scanErr := client.client.Keys(context.Background(), prefix+":*").Result()
		if scanErr == nil && len(keys) > 0 {
			_ = client.client.Del(context.Background(), keys...).Err()
		}
		_ = client.Close()
	})

	if got := client.client.Options().Protocol; got != 3 {
		t.Fatalf("negotiated protocol option = %d, want RESP3", got)
	}
	name, err := client.client.ClientGetName(ctx).Result()
	if err != nil {
		t.Fatalf("CLIENT GETNAME: %v", err)
	}
	if name != "aegrail-hub" {
		t.Fatalf("Redis client name = %q, want aegrail-hub", name)
	}

	if err := client.Enqueue(ctx, "correlation", []byte("first")); err != nil {
		t.Fatalf("enqueue first payload: %v", err)
	}
	if err := client.Enqueue(ctx, "correlation", []byte("second")); err != nil {
		t.Fatalf("enqueue second payload: %v", err)
	}
	for index, want := range []string{"first", "second"} {
		payload, err := client.Dequeue(ctx, "correlation", time.Second)
		if err != nil {
			t.Fatalf("dequeue payload %d: %v", index, err)
		}
		if string(payload) != want {
			t.Fatalf("dequeue payload %d = %q, want %q", index, payload, want)
		}
	}

	allowed, err := client.Allow(ctx, "login:operator", 2, time.Minute)
	if err != nil || !allowed {
		t.Fatalf("first rate-limit check = %t, %v; want allowed", allowed, err)
	}
	allowed, err = client.Allow(ctx, "login:operator", 2, time.Minute)
	if err != nil || !allowed {
		t.Fatalf("second rate-limit check = %t, %v; want allowed", allowed, err)
	}
	allowed, err = client.Allow(ctx, "login:operator", 2, time.Minute)
	if err != nil || allowed {
		t.Fatalf("third rate-limit check = %t, %v; want denied", allowed, err)
	}
	rateKey, err := client.rateLimitKey("login:operator")
	if err != nil {
		t.Fatalf("rate-limit key: %v", err)
	}
	if ttl, err := client.client.PTTL(ctx, rateKey).Result(); err != nil || ttl <= 0 {
		t.Fatalf("rate-limit TTL = %s, %v; want positive TTL", ttl, err)
	}
	if loaded, err := rateLimitAllowScript.Exists(ctx, client.client).Result(); err != nil || len(loaded) != 1 || !loaded[0] {
		t.Fatalf("rate-limit script cached = %v, %v; want true", loaded, err)
	}

	lock, acquired, err := client.TryLock(ctx, "model-analysis", time.Minute)
	if err != nil || !acquired {
		t.Fatalf("acquire lock = %t, %v; want acquired", acquired, err)
	}
	if _, acquired, err := client.TryLock(ctx, "model-analysis", time.Minute); err != nil || acquired {
		t.Fatalf("acquire held lock = %t, %v; want unavailable", acquired, err)
	}
	if err := client.client.ScriptFlush(ctx).Err(); err != nil {
		t.Fatalf("flush Redis script cache: %v", err)
	}
	if err := lock.Release(ctx); err != nil {
		t.Fatalf("release lock after SCRIPT FLUSH: %v", err)
	}
	lock, acquired, err = client.TryLock(ctx, "model-analysis", time.Minute)
	if err != nil || !acquired {
		t.Fatalf("reacquire released lock = %t, %v; want acquired", acquired, err)
	}
	if err := lock.Release(ctx); err != nil {
		t.Fatalf("release reacquired lock: %v", err)
	}
}

func randomRedisHex(t *testing.T, byteCount int) string {
	t.Helper()
	buffer := make([]byte, byteCount)
	if _, err := rand.Read(buffer); err != nil {
		t.Fatalf("read random bytes: %v", err)
	}
	return hex.EncodeToString(buffer)
}
