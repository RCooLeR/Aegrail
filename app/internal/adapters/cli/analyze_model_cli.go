package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/rcooler/aegrail/internal/bootstrap"
	"github.com/rcooler/aegrail/internal/domain"
	hubapp "github.com/rcooler/aegrail/internal/hub"
	"github.com/rcooler/aegrail/internal/ports"
	"github.com/rcooler/aegrail/internal/reports"
	urfavecli "github.com/urfave/cli/v2"
)

func analyzeModelCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "model",
		Usage: "inspect and smoke-test the configured model gateway",
		Subcommands: []*urfavecli.Command{
			modelStatusCommand(meta),
			modelPromptCommand(meta),
			modelEmbedCommand(meta),
			modelReportCommand(meta),
		},
	}
}

func modelStatusCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "status",
		Usage: "show configured model gateway status",
		Action: func(c *urfavecli.Context) error {
			container, err := newModelContainer(meta)
			if err != nil {
				return err
			}
			defer container.Close()

			health, err := container.Model.Health(c.Context)
			if err != nil {
				return err
			}
			fmt.Fprintf(c.App.Writer, "Provider: %s\n", health.Provider)
			fmt.Fprintf(c.App.Writer, "Base URL: %s\n", health.BaseURL)
			fmt.Fprintf(c.App.Writer, "Offline: %t\n", health.Offline)
			fmt.Fprintf(c.App.Writer, "Available: %t\n", health.Available)
			fmt.Fprintf(c.App.Writer, "Investigation model: %s\n", emptyDash(health.InvestigationModel))
			fmt.Fprintf(c.App.Writer, "Embedding model: %s\n", emptyDash(health.EmbeddingModel))
			if len(health.Models) == 0 {
				fmt.Fprintln(c.App.Writer, "Models: none reported")
				return nil
			}
			writer := tabwriter.NewWriter(c.App.Writer, 0, 0, 2, ' ', 0)
			fmt.Fprintln(writer, "MODEL\tSIZE\tDIGEST\tMODIFIED")
			for _, model := range health.Models {
				fmt.Fprintf(writer, "%s\t%d\t%s\t%s\n", model.Name, model.SizeBytes, shortDigest(model.Digest), modelTime(model.ModifiedAt))
			}
			return writer.Flush()
		},
	}
}

func modelPromptCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:      "prompt",
		Usage:     "send one non-streaming prompt to the configured investigation model",
		ArgsUsage: "[prompt]",
		Flags: []urfavecli.Flag{
			&urfavecli.StringFlag{Name: "model", Usage: "override investigation model"},
			&urfavecli.StringFlag{Name: "system", Usage: "optional system instruction"},
			&urfavecli.StringFlag{Name: "prompt", Usage: "prompt text; positional args are used when omitted"},
			&urfavecli.StringFlag{Name: "format", Value: "text", Usage: "text or json"},
		},
		Action: func(c *urfavecli.Context) error {
			prompt := strings.TrimSpace(c.String("prompt"))
			if prompt == "" && c.NArg() > 0 {
				prompt = strings.Join(c.Args().Slice(), " ")
			}
			if prompt == "" {
				return errors.New("prompt is required")
			}

			container, err := newModelContainer(meta)
			if err != nil {
				return err
			}
			defer container.Close()

			response, err := container.Model.Generate(c.Context, ports.ModelGenerateRequest{
				Model:  c.String("model"),
				System: c.String("system"),
				Prompt: prompt,
			})
			if err != nil {
				if errors.Is(err, ports.ErrModelGatewayOffline) {
					return errors.New("model gateway is offline; set AEGRAIL_OLLAMA_OFFLINE=false to enable model calls")
				}
				return err
			}
			if strings.EqualFold(c.String("format"), "json") {
				return json.NewEncoder(c.App.Writer).Encode(response)
			}
			fmt.Fprintln(c.App.Writer, response.Text)
			return nil
		},
	}
}

func modelEmbedCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:      "embed",
		Usage:     "send one embedding request to the configured embedding model",
		ArgsUsage: "[text]",
		Flags: []urfavecli.Flag{
			&urfavecli.StringFlag{Name: "model", Usage: "override embedding model"},
			&urfavecli.StringFlag{Name: "text", Usage: "text to embed; positional args are used when omitted"},
			&urfavecli.StringFlag{Name: "format", Value: "summary", Usage: "summary or json"},
		},
		Action: func(c *urfavecli.Context) error {
			text := strings.TrimSpace(c.String("text"))
			if text == "" && c.NArg() > 0 {
				text = strings.Join(c.Args().Slice(), " ")
			}
			if text == "" {
				return errors.New("text is required")
			}

			container, err := newModelContainer(meta)
			if err != nil {
				return err
			}
			defer container.Close()

			response, err := container.Model.Embed(c.Context, ports.ModelEmbedRequest{
				Model: c.String("model"),
				Texts: []string{
					text,
				},
			})
			if err != nil {
				if errors.Is(err, ports.ErrModelGatewayOffline) {
					return errors.New("model gateway is offline; set AEGRAIL_OLLAMA_OFFLINE=false to enable model calls")
				}
				return err
			}
			if strings.EqualFold(c.String("format"), "json") {
				return json.NewEncoder(c.App.Writer).Encode(response)
			}
			dimension := 0
			if len(response.Embeddings) > 0 {
				dimension = len(response.Embeddings[0])
			}
			fmt.Fprintf(c.App.Writer, "Model %s produced %d embedding vector(s), dimension %d.\n", response.Model, len(response.Embeddings), dimension)
			return nil
		},
	}
}

func modelReportCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "report",
		Usage: "generate a prompt-versioned model analysis report from persisted Hub findings",
		Flags: append(environmentPathFlags(),
			&urfavecli.StringFlag{Name: "app", Usage: "optional monitored app slug"},
			&urfavecli.StringFlag{Name: "model", Usage: "override investigation model"},
			&urfavecli.StringFlag{Name: "format", Value: "json", Usage: "output format"},
			&urfavecli.StringFlag{Name: "output", Aliases: []string{"o"}, Usage: "write report to a file instead of stdout"},
			&urfavecli.IntFlag{Name: "limit", Value: 20, Usage: "maximum findings to include"},
			&urfavecli.IntFlag{Name: "max-events", Value: 8, Usage: "maximum compact evidence events per finding"},
			&urfavecli.IntFlag{Name: "max-metadata-depth", Value: 4, Usage: "maximum nested metadata depth"},
			&urfavecli.IntFlag{Name: "max-string-length", Value: 500, Usage: "maximum string length in redacted metadata"},
			&urfavecli.BoolFlag{Name: "save", Usage: "persist the generated report in the Hub"},
			&urfavecli.BoolFlag{Name: "compact", Usage: "write compact JSON without indentation"},
		),
		Action: func(c *urfavecli.Context) error {
			container, cleanup, err := newDatabaseContainer(c.Context, meta)
			if err != nil {
				return err
			}
			defer cleanup()

			now := time.Now().UTC()
			findings, err := container.Hub.ListHubFindings(c.Context, hubapp.ListHubFindingsInput{
				OrganizationSlug: c.String("org"),
				ProjectSlug:      c.String("project"),
				EnvironmentSlug:  c.String("env"),
				AppSlug:          c.String("app"),
				Limit:            c.Int("limit"),
			})
			if err != nil {
				return err
			}

			findingsReport := reports.BuildHubFindingsJSONReport(meta, reports.HubFindingsScope{
				Organization: c.String("org"),
				Project:      c.String("project"),
				Environment:  c.String("env"),
				App:          c.String("app"),
			}, findings, now)
			bundle, err := reports.BuildEvidenceBundle(findingsReport, reports.EvidenceBundleOptions{
				MaxFindings:         c.Int("limit"),
				MaxEventsPerFinding: c.Int("max-events"),
				MaxMetadataDepth:    c.Int("max-metadata-depth"),
				MaxStringLength:     c.Int("max-string-length"),
			})
			if err != nil {
				return err
			}

			report, err := reports.GenerateModelAnalysisReport(c.Context, container.Model, bundle, reports.ModelAnalysisOptions{
				Model: c.String("model"),
			}, now)
			if err != nil {
				return err
			}
			if c.Bool("save") {
				saved, err := container.Hub.SaveModelAnalysisReport(c.Context, hubapp.SaveModelAnalysisReportInput{
					OrganizationSlug: c.String("org"),
					ProjectSlug:      c.String("project"),
					EnvironmentSlug:  c.String("env"),
					AppSlug:          c.String("app"),
					Report:           reports.DomainModelAnalysisReport(report),
				})
				if err != nil {
					return err
				}
				report = reports.ApplySavedModelAnalysisReport(report, saved)
			}

			writer, closeWriter, err := reportWriter(c, c.String("output"))
			if err != nil {
				return err
			}
			defer closeWriter()

			return writeModelAnalysisReport(writer, c.String("format"), report, c.Bool("compact"))
		},
	}
}

func writeModelAnalysisReport(w io.Writer, format string, report reports.ModelAnalysisReport, compact bool) error {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "json":
		return reports.WriteModelAnalysisReportJSON(w, report, !compact)
	default:
		return fmt.Errorf("unsupported report format %q", format)
	}
}

func newModelContainer(meta domain.AppMeta) (*bootstrap.Container, error) {
	return bootstrap.NewContainer(meta)
}

func emptyDash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

func shortDigest(value string) string {
	if len(value) <= 12 {
		return value
	}
	return value[:12]
}

func modelTime(value time.Time) string {
	if value.IsZero() {
		return "-"
	}
	return value.UTC().Format(time.RFC3339)
}
