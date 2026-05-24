package collector

import (
	"database/sql"
	"errors"
	"sync"
)

type Runtime struct {
	Config       Config
	databaseMu   sync.Mutex
	databasePool map[string]*sql.DB
}

type Config struct {
	Name string
}

func NewRuntime(config Config) *Runtime {
	return &Runtime{Config: config}
}

func (r *Runtime) Close() error {
	r.databaseMu.Lock()
	pool := r.databasePool
	r.databasePool = nil
	r.databaseMu.Unlock()

	var errs []error
	for _, db := range pool {
		if err := db.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
