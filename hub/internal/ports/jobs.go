package ports

import (
	"context"
	"errors"
	"time"
)

var ErrQueueTimeout = errors.New("queue dequeue timed out")

type JobQueue interface {
	Enqueue(ctx context.Context, queue string, payload []byte) error
	Dequeue(ctx context.Context, queue string, timeout time.Duration) ([]byte, error)
}

type LockManager interface {
	TryLock(ctx context.Context, key string, ttl time.Duration) (DistributedLock, bool, error)
}

type DistributedLock interface {
	Release(ctx context.Context) error
}
