package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rcooler/aegrail/internal/domain"
	hubapp "github.com/rcooler/aegrail/internal/hub"
	"github.com/rcooler/aegrail/internal/reports"
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

func writeHubFindingsReport(w io.Writer, format string, report reports.HubFindingsJSONReport, compact bool) error {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "json":
		return reports.WriteHubFindingsJSON(w, report, !compact)
	case "markdown", "md":
		return reports.WriteHubFindingsMarkdown(w, report)
	default:
		return fmt.Errorf("unsupported report format %q", format)
	}
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
