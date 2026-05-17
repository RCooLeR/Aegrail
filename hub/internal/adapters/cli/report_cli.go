package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/rcooler/aegrail/hub/internal/domain"
	hubapp "github.com/rcooler/aegrail/hub/internal/hub"
	"github.com/rcooler/aegrail/hub/internal/reports"
	urfavecli "github.com/urfave/cli/v2"
)

func hubFindingsReportCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "hub-findings",
		Usage: "export persisted Hub findings",
		Flags: append(environmentPathFlags(),
			&urfavecli.StringFlag{Name: "app", Usage: "optional monitored app slug"},
			&urfavecli.StringFlag{Name: "format", Value: "json", Usage: "output format"},
			&urfavecli.StringFlag{Name: "output", Aliases: []string{"o"}, Usage: "write report to a file instead of stdout"},
			&urfavecli.IntFlag{Name: "limit", Value: 100, Usage: "maximum findings to export"},
			&urfavecli.BoolFlag{Name: "compact", Usage: "write compact JSON without indentation"},
		),
		Action: func(c *urfavecli.Context) error {
			container, cleanup, err := newDatabaseContainer(c.Context, meta)
			if err != nil {
				return err
			}
			defer cleanup()

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

			report := reports.BuildHubFindingsJSONReport(meta, reports.HubFindingsScope{
				Organization: c.String("org"),
				Project:      c.String("project"),
				Environment:  c.String("env"),
				App:          c.String("app"),
			}, findings, time.Now().UTC())

			writer, closeWriter, err := reportWriter(c, c.String("output"))
			if err != nil {
				return err
			}
			defer closeWriter()

			return writeHubFindingsReport(writer, c.String("format"), report, c.Bool("compact"))
		},
	}
}

func timelineReportCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "timeline",
		Usage: "export Hub timeline events",
		Flags: append(environmentPathFlags(),
			&urfavecli.StringFlag{Name: "app", Usage: "optional monitored app slug"},
			&urfavecli.StringFlag{Name: "since", Value: "24h", Usage: "lookback window such as 24h, 7d, or an RFC3339 timestamp"},
			&urfavecli.StringFlag{Name: "format", Value: "csv", Usage: "output format"},
			&urfavecli.StringFlag{Name: "output", Aliases: []string{"o"}, Usage: "write report to a file instead of stdout"},
			&urfavecli.IntFlag{Name: "limit", Value: 1000, Usage: "maximum timeline events to export"},
		),
		Action: func(c *urfavecli.Context) error {
			since, err := parseLookback(c.String("since"), time.Now)
			if err != nil {
				return err
			}
			container, cleanup, err := newDatabaseContainer(c.Context, meta)
			if err != nil {
				return err
			}
			defer cleanup()

			events, err := container.Hub.ListTimelineEvents(c.Context, hubapp.ListTimelineEventsInput{
				OrganizationSlug: c.String("org"),
				ProjectSlug:      c.String("project"),
				EnvironmentSlug:  c.String("env"),
				AppSlug:          c.String("app"),
				Since:            since,
				Limit:            c.Int("limit"),
			})
			if err != nil {
				return err
			}

			report := reports.BuildTimelineCSVReport(meta, reports.TimelineCSVScope{
				Organization: c.String("org"),
				Project:      c.String("project"),
				Environment:  c.String("env"),
				App:          c.String("app"),
			}, events, time.Now().UTC())

			writer, closeWriter, err := reportWriter(c, c.String("output"))
			if err != nil {
				return err
			}
			defer closeWriter()

			return writeTimelineReport(writer, c.String("format"), report)
		},
	}
}

func evidenceBundleReportCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "evidence-bundle",
		Usage: "export a compact redacted evidence bundle for model-assisted analysis",
		Flags: append(environmentPathFlags(),
			&urfavecli.StringFlag{Name: "app", Usage: "optional monitored app slug"},
			&urfavecli.StringFlag{Name: "format", Value: "json", Usage: "output format"},
			&urfavecli.StringFlag{Name: "output", Aliases: []string{"o"}, Usage: "write bundle to a file instead of stdout"},
			&urfavecli.IntFlag{Name: "limit", Value: 50, Usage: "maximum findings to include"},
			&urfavecli.IntFlag{Name: "max-events", Value: 8, Usage: "maximum compact evidence events per finding"},
			&urfavecli.IntFlag{Name: "max-metadata-depth", Value: 4, Usage: "maximum nested metadata depth"},
			&urfavecli.IntFlag{Name: "max-string-length", Value: 500, Usage: "maximum string length in redacted metadata"},
			&urfavecli.BoolFlag{Name: "compact", Usage: "write compact JSON without indentation"},
		),
		Action: func(c *urfavecli.Context) error {
			container, cleanup, err := newDatabaseContainer(c.Context, meta)
			if err != nil {
				return err
			}
			defer cleanup()

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

			report := reports.BuildHubFindingsJSONReport(meta, reports.HubFindingsScope{
				Organization: c.String("org"),
				Project:      c.String("project"),
				Environment:  c.String("env"),
				App:          c.String("app"),
			}, findings, time.Now().UTC())
			bundle, err := reports.BuildEvidenceBundle(report, reports.EvidenceBundleOptions{
				MaxFindings:         c.Int("limit"),
				MaxEventsPerFinding: c.Int("max-events"),
				MaxMetadataDepth:    c.Int("max-metadata-depth"),
				MaxStringLength:     c.Int("max-string-length"),
			})
			if err != nil {
				return err
			}

			writer, closeWriter, err := reportWriter(c, c.String("output"))
			if err != nil {
				return err
			}
			defer closeWriter()

			return writeEvidenceBundleReport(writer, c.String("format"), bundle, c.Bool("compact"))
		},
	}
}

func findingReviewReportCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "finding-review",
		Usage: "export deterministic findings side by side with latest model analysis",
		Flags: append(environmentPathFlags(),
			&urfavecli.StringFlag{Name: "app", Usage: "optional monitored app slug"},
			&urfavecli.StringFlag{Name: "format", Value: "markdown", Usage: "markdown or json"},
			&urfavecli.StringFlag{Name: "output", Aliases: []string{"o"}, Usage: "write report to a file instead of stdout"},
			&urfavecli.IntFlag{Name: "limit", Value: 100, Usage: "maximum findings and model reports to inspect"},
			&urfavecli.BoolFlag{Name: "compact", Usage: "write compact JSON without indentation"},
		),
		Action: func(c *urfavecli.Context) error {
			container, cleanup, err := newDatabaseContainer(c.Context, meta)
			if err != nil {
				return err
			}
			defer cleanup()

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
			modelReports, err := container.Hub.ListModelAnalysisReports(c.Context, hubapp.ListModelAnalysisReportsInput{
				OrganizationSlug: c.String("org"),
				ProjectSlug:      c.String("project"),
				EnvironmentSlug:  c.String("env"),
				AppSlug:          c.String("app"),
				Limit:            c.Int("limit"),
			})
			if err != nil {
				return err
			}

			report := reports.BuildFindingReviewReport(meta, reports.HubFindingsScope{
				Organization: c.String("org"),
				Project:      c.String("project"),
				Environment:  c.String("env"),
				App:          c.String("app"),
			}, findings, modelReports, time.Now().UTC())

			writer, closeWriter, err := reportWriter(c, c.String("output"))
			if err != nil {
				return err
			}
			defer closeWriter()

			return writeFindingReviewReport(writer, c.String("format"), report, c.Bool("compact"))
		},
	}
}

func modelAnalysisReportCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "model-analysis",
		Usage: "inspect saved model analysis reports",
		Subcommands: []*urfavecli.Command{
			modelAnalysisReportListCommand(meta),
			modelAnalysisReportShowCommand(meta),
		},
	}
}

func modelAnalysisReportListCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "list",
		Usage: "list saved model analysis reports",
		Flags: append(environmentPathFlags(),
			&urfavecli.StringFlag{Name: "app", Usage: "optional monitored app slug"},
			&urfavecli.IntFlag{Name: "limit", Value: 20, Usage: "maximum reports to list"},
			&urfavecli.StringFlag{Name: "format", Value: "table", Usage: "table or json"},
		),
		Action: func(c *urfavecli.Context) error {
			container, cleanup, err := newDatabaseContainer(c.Context, meta)
			if err != nil {
				return err
			}
			defer cleanup()

			reports, err := container.Hub.ListModelAnalysisReports(c.Context, hubapp.ListModelAnalysisReportsInput{
				OrganizationSlug: c.String("org"),
				ProjectSlug:      c.String("project"),
				EnvironmentSlug:  c.String("env"),
				AppSlug:          c.String("app"),
				Limit:            c.Int("limit"),
			})
			if err != nil {
				return err
			}
			return writeModelAnalysisReportList(c.App.Writer, c.String("format"), reports)
		},
	}
}

func modelAnalysisReportShowCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "show",
		Usage: "show one saved model analysis report",
		Flags: append(environmentPathFlags(),
			&urfavecli.StringFlag{Name: "app", Usage: "optional monitored app slug"},
			&urfavecli.StringFlag{Name: "id", Required: true, Usage: "model analysis report id"},
			&urfavecli.StringFlag{Name: "format", Value: "json", Usage: "json or summary"},
		),
		Action: func(c *urfavecli.Context) error {
			container, cleanup, err := newDatabaseContainer(c.Context, meta)
			if err != nil {
				return err
			}
			defer cleanup()

			report, err := container.Hub.GetModelAnalysisReport(c.Context, hubapp.GetModelAnalysisReportInput{
				OrganizationSlug: c.String("org"),
				ProjectSlug:      c.String("project"),
				EnvironmentSlug:  c.String("env"),
				AppSlug:          c.String("app"),
				ReportID:         c.String("id"),
			})
			if err != nil {
				return err
			}
			return writeModelAnalysisReportDetail(c.App.Writer, c.String("format"), report)
		},
	}
}

func writeHubFindingsReport(w io.Writer, format string, report reports.HubFindingsJSONReport, compact bool) error {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "json":
		return reports.WriteHubFindingsJSON(w, report, !compact)
	case "markdown", "md":
		return reports.WriteHubFindingsMarkdown(w, report)
	case "manager-markdown", "manager-md", "manager-summary", "summary":
		return reports.WriteHubFindingsManagerMarkdown(w, report)
	default:
		return fmt.Errorf("unsupported report format %q", format)
	}
}

func writeTimelineReport(w io.Writer, format string, report reports.TimelineCSVReport) error {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "csv":
		return reports.WriteTimelineCSV(w, report)
	default:
		return fmt.Errorf("unsupported report format %q", format)
	}
}

func writeEvidenceBundleReport(w io.Writer, format string, bundle reports.EvidenceBundle, compact bool) error {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "json":
		return reports.WriteEvidenceBundleJSON(w, bundle, !compact)
	default:
		return fmt.Errorf("unsupported report format %q", format)
	}
}

func writeFindingReviewReport(w io.Writer, format string, report reports.FindingReviewReport, compact bool) error {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "markdown", "md":
		return reports.WriteFindingReviewMarkdown(w, report)
	case "json":
		return reports.WriteFindingReviewJSON(w, report, !compact)
	default:
		return fmt.Errorf("unsupported report format %q", format)
	}
}

type storedModelAnalysisReportResponse struct {
	ID                             string         `json:"id"`
	AppID                          string         `json:"app_id,omitempty"`
	Schema                         string         `json:"schema"`
	Status                         string         `json:"status"`
	ModelProvider                  string         `json:"model_provider,omitempty"`
	ModelName                      string         `json:"model_name,omitempty"`
	PromptTemplateID               string         `json:"prompt_template_id"`
	PromptTemplateVersion          string         `json:"prompt_template_version"`
	PromptTemplateSHA256           string         `json:"prompt_template_sha256"`
	PromptSHA256                   string         `json:"prompt_sha256"`
	EvidenceBundleSchema           string         `json:"evidence_bundle_schema"`
	EvidenceBundleSHA256           string         `json:"evidence_bundle_sha256"`
	EvidenceBundleRedactionVersion string         `json:"evidence_bundle_redaction_version"`
	EvidenceBundleGeneratedAt      time.Time      `json:"evidence_bundle_generated_at"`
	SourceFindingIDs               []string       `json:"source_finding_ids"`
	Analysis                       string         `json:"analysis,omitempty"`
	Error                          string         `json:"error,omitempty"`
	TotalDurationMillis            int64          `json:"total_duration_millis,omitempty"`
	PromptEvalCount                int            `json:"prompt_eval_count,omitempty"`
	EvalCount                      int            `json:"eval_count,omitempty"`
	GeneratedAt                    time.Time      `json:"generated_at"`
	Metadata                       map[string]any `json:"metadata"`
	CreatedAt                      time.Time      `json:"created_at"`
}

func writeModelAnalysisReportList(w io.Writer, format string, reports []domain.ModelAnalysisReport) error {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "table":
		if len(reports) == 0 {
			_, err := fmt.Fprintln(w, "No model analysis reports found.")
			return err
		}
		writer := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(writer, "GENERATED\tSTATUS\tMODEL\tPROMPT\tBUNDLE\tFINDINGS\tID")
		for _, report := range reports {
			fmt.Fprintf(
				writer,
				"%s\t%s\t%s\t%s\t%s\t%d\t%s\n",
				report.GeneratedAt.UTC().Format(time.RFC3339),
				report.Status,
				emptyDash(report.ModelName),
				report.PromptTemplateVersion,
				shortDigest(report.EvidenceBundleSHA256),
				len(report.SourceFindingIDs),
				report.ID,
			)
		}
		return writer.Flush()
	case "json":
		records := make([]storedModelAnalysisReportResponse, 0, len(reports))
		for _, report := range reports {
			records = append(records, storedModelAnalysisReportRecord(report))
		}
		return json.NewEncoder(w).Encode(map[string]any{
			"count":   len(records),
			"reports": records,
		})
	default:
		return fmt.Errorf("unsupported report format %q", format)
	}
}

func writeModelAnalysisReportDetail(w io.Writer, format string, report domain.ModelAnalysisReport) error {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "json":
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		return encoder.Encode(storedModelAnalysisReportRecord(report))
	case "summary":
		fmt.Fprintf(w, "ID: %s\n", report.ID)
		fmt.Fprintf(w, "Generated: %s\n", report.GeneratedAt.UTC().Format(time.RFC3339))
		fmt.Fprintf(w, "Status: %s\n", report.Status)
		fmt.Fprintf(w, "Model: %s\n", emptyDash(report.ModelName))
		fmt.Fprintf(w, "Prompt: %s %s\n", report.PromptTemplateID, report.PromptTemplateVersion)
		fmt.Fprintf(w, "Bundle: %s\n", report.EvidenceBundleSHA256)
		if report.Error != "" {
			fmt.Fprintf(w, "Error: %s\n", report.Error)
		}
		if report.Analysis != "" {
			fmt.Fprintf(w, "\n%s\n", compactText(report.Analysis, 2000))
		}
		return nil
	default:
		return fmt.Errorf("unsupported report format %q", format)
	}
}

func storedModelAnalysisReportRecord(report domain.ModelAnalysisReport) storedModelAnalysisReportResponse {
	return storedModelAnalysisReportResponse{
		ID:                             string(report.ID),
		AppID:                          string(report.AppID),
		Schema:                         report.ReportSchema,
		Status:                         report.Status,
		ModelProvider:                  report.ModelProvider,
		ModelName:                      report.ModelName,
		PromptTemplateID:               report.PromptTemplateID,
		PromptTemplateVersion:          report.PromptTemplateVersion,
		PromptTemplateSHA256:           report.PromptTemplateSHA256,
		PromptSHA256:                   report.PromptSHA256,
		EvidenceBundleSchema:           report.EvidenceBundleSchema,
		EvidenceBundleSHA256:           report.EvidenceBundleSHA256,
		EvidenceBundleRedactionVersion: report.EvidenceBundleRedactionVersion,
		EvidenceBundleGeneratedAt:      report.EvidenceBundleGeneratedAt,
		SourceFindingIDs:               modelReportFindingIDs(report.SourceFindingIDs),
		Analysis:                       report.Analysis,
		Error:                          report.Error,
		TotalDurationMillis:            report.TotalDurationMillis,
		PromptEvalCount:                report.PromptEvalCount,
		EvalCount:                      report.EvalCount,
		GeneratedAt:                    report.GeneratedAt,
		Metadata:                       nonNilStoredReportMetadata(report.Metadata),
		CreatedAt:                      report.CreatedAt,
	}
}

func modelReportFindingIDs(ids []domain.ID) []string {
	values := make([]string, 0, len(ids))
	for _, id := range ids {
		values = append(values, string(id))
	}
	return values
}

func nonNilStoredReportMetadata(metadata map[string]any) map[string]any {
	if metadata == nil {
		return map[string]any{}
	}
	return metadata
}

func reportWriter(c *urfavecli.Context, outputPath string) (io.Writer, func(), error) {
	if outputPath == "" {
		return c.App.Writer, func() {}, nil
	}
	if dir := filepath.Dir(outputPath); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, func() {}, err
		}
	}
	file, err := os.Create(outputPath)
	if err != nil {
		return nil, func() {}, err
	}
	return file, func() { _ = file.Close() }, nil
}
