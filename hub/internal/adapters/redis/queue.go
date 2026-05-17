package redis

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/rcooler/aegrail/hub/internal/ports"
	goredis "github.com/redis/go-redis/v9"
)

type Config struct {
	URL       string
	KeyPrefix string
}

type Client struct {
	client    *goredis.Client
	keyPrefix string
}

func NewClient(ctx context.Context, cfg Config) (*Client, error) {
	url := strings.TrimSpace(cfg.URL)
	if url == "" {
		return nil, errors.New("redis url is required")
	}
	options, err := goredis.ParseURL(url)
	if err != nil {
		return nil, fmt.Errorf("parse redis url: %w", err)
	}
	client := goredis.NewClient(options)
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("connect redis: %w", err)
	}
	prefix := strings.TrimSpace(cfg.KeyPrefix)
	if prefix == "" {
		prefix = "aegrail"
	}
	return &Client{
		client:    client,
		keyPrefix: prefix,
	}, nil
}

func (c *Client) Close() error {
	if c == nil || c.client == nil {
		return nil
	}
	return c.client.Close()
}

func (c *Client) Enqueue(ctx context.Context, queue string, payload []byte) error {
	key, err := c.queueKey(queue)
	if err != nil {
		return err
	}
	if len(payload) == 0 {
		return errors.New("queue payload is required")
	}
	return c.client.RPush(ctx, key, payload).Err()
}

func (c *Client) Dequeue(ctx context.Context, queue string, timeout time.Duration) ([]byte, error) {
	key, err := c.queueKey(queue)
	if err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	result, err := c.client.BLPop(ctx, timeout, key).Result()
	if err != nil {
		if errors.Is(err, goredis.Nil) {
			return nil, ports.ErrQueueTimeout
		}
		return nil, err
	}
	if len(result) != 2 {
		return nil, fmt.Errorf("redis returned malformed queue result for %q", queue)
	}
	return []byte(result[1]), nil
}

func (c *Client) TryLock(ctx context.Context, key string, ttl time.Duration) (ports.DistributedLock, bool, error) {
	lockKey, err := c.lockKey(key)
	if err != nil {
		return nil, false, err
	}
	if ttl <= 0 {
		ttl = time.Minute
	}
	token, err := randomToken()
	if err != nil {
		return nil, false, err
	}
	ok, err := c.client.SetNX(ctx, lockKey, token, ttl).Result()
	if err != nil || !ok {
		return nil, ok, err
	}
	return &redisLock{
		client: c.client,
		key:    lockKey,
		token:  token,
	}, true, nil
}

func (c *Client) queueKey(queue string) (string, error) {
	name := strings.TrimSpace(queue)
	if name == "" {
		return "", errors.New("queue name is required")
	}
	return c.keyPrefix + ":queue:" + name, nil
}

func (c *Client) lockKey(key string) (string, error) {
	name := strings.TrimSpace(key)
	if name == "" {
		return "", errors.New("lock key is required")
	}
	return c.keyPrefix + ":lock:" + name, nil
}

type redisLock struct {
	client *goredis.Client
	key    string
	token  string
}

func (l *redisLock) Release(ctx context.Context) error {
	const releaseScript = `
if redis.call("get", KEYS[1]) == ARGV[1] then
  return redis.call("del", KEYS[1])
end
return 0`
	return l.client.Eval(ctx, releaseScript, []string{l.key}, l.token).Err()
}

func randomToken() (string, error) {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes[:]), nil
}
