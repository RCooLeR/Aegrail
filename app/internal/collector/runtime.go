package collector

type Runtime struct {
	Config Config
}

type Config struct {
	Name string
}

func NewRuntime(config Config) *Runtime {
	return &Runtime{Config: config}
}
