package hub

import (
	"context"
	"runtime/pprof"
)

const hubWorkerLabelKey = "aegrail.worker"

func runHubWorker(ctx context.Context, name string, work func(context.Context)) {
	pprof.Do(ctx, pprof.Labels(hubWorkerLabelKey, name), work)
}
