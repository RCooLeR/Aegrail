package ports

import (
	"context"

	"github.com/rcooler/aegrail/internal/domain"
)

type BrowserScriptAllowlistRepository interface {
	SaveBrowserScriptAllowlistEntry(ctx context.Context, entry domain.BrowserScriptAllowlistEntry) (domain.BrowserScriptAllowlistEntry, error)
	ListBrowserScriptAllowlistEntries(ctx context.Context, environmentID domain.ID, appID domain.ID) ([]domain.BrowserScriptAllowlistEntry, error)
}
