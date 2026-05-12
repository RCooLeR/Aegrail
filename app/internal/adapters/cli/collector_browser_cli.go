package cli

import (
	"encoding/json"
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/rcooler/aegrail/internal/collector"
	"github.com/rcooler/aegrail/internal/domain"
	hubapp "github.com/rcooler/aegrail/internal/hub"
	urfavecli "github.com/urfave/cli/v2"
)

func collectorBrowserCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "browser",
		Usage: "crawl rendered-page-adjacent browser evidence",
		Subcommands: []*urfavecli.Command{
			{
				Name:  "crawl",
				Usage: "crawl pages and inventory scripts from static HTML or rendered browser state",
				Flags: []urfavecli.Flag{
					&urfavecli.StringSliceFlag{Name: "url", Aliases: []string{"u"}, Required: true, Usage: "page URL to crawl; repeat for multiple pages"},
					&urfavecli.IntFlag{Name: "max-pages", Value: 10, Usage: "maximum supplied URLs to crawl"},
					&urfavecli.DurationFlag{Name: "timeout", Value: 15 * time.Second, Usage: "per-page HTTP timeout"},
					&urfavecli.StringFlag{Name: "user-agent", Usage: "override crawler User-Agent"},
					&urfavecli.BoolFlag{Name: "same-host-only", Usage: "skip supplied URLs outside the seed host set"},
					&urfavecli.BoolFlag{Name: "rendered", Usage: "use a headless browser to observe scripts after JavaScript execution"},
					&urfavecli.DurationFlag{Name: "network-idle", Value: 1500 * time.Millisecond, Usage: "rendered mode quiet-network period before extraction"},
					&urfavecli.DurationFlag{Name: "settle", Value: 2 * time.Second, Usage: "rendered mode extra settle wait after network idle"},
					&urfavecli.BoolFlag{Name: "wait-tag-manager", Usage: "rendered mode waits briefly for Google Tag Manager or Google tag readiness"},
					&urfavecli.BoolFlag{Name: "ingest", Usage: "save crawl observations into Hub ingest events"},
					&urfavecli.StringFlag{Name: "org", Usage: "Hub organization slug for --ingest"},
					&urfavecli.StringFlag{Name: "project", Usage: "Hub project slug for --ingest"},
					&urfavecli.StringFlag{Name: "env", Usage: "Hub environment slug for --ingest"},
					&urfavecli.StringFlag{Name: "app", Usage: "Hub monitored app slug for --ingest"},
					&urfavecli.StringFlag{Name: "service", Usage: "Hub service slug for --ingest"},
					&urfavecli.StringFlag{Name: "host", Usage: "Hub host slug for --ingest"},
					&urfavecli.StringFlag{Name: "agent-id", Usage: "Hub agent id for --ingest"},
					&urfavecli.StringFlag{Name: "batch-id", Usage: "Hub external batch id for --ingest; generated when omitted"},
					&urfavecli.StringFlag{Name: "region", Usage: "Hub event region for --ingest"},
					&urfavecli.StringSliceFlag{Name: "label", Usage: "Hub event label for --ingest as key=value; repeatable"},
					&urfavecli.StringFlag{Name: "format", Value: "table", Usage: "output format: table or json"},
				},
				Action: func(c *urfavecli.Context) error {
					runtime := collector.NewRuntime(collector.Config{Name: "browser"})
					result, err := runtime.CrawlBrowserPages(c.Context, collector.BrowserCrawlInput{
						URLs:           c.StringSlice("url"),
						MaxPages:       c.Int("max-pages"),
						Timeout:        c.Duration("timeout"),
						UserAgent:      c.String("user-agent"),
						SameHostOnly:   c.Bool("same-host-only"),
						Rendered:       c.Bool("rendered"),
						NetworkIdle:    c.Duration("network-idle"),
						Settle:         c.Duration("settle"),
						WaitTagManager: c.Bool("wait-tag-manager"),
					})
					if err != nil {
						return err
					}
					var ingestResult *hubapp.IngestEventsResult
					if c.Bool("ingest") {
						saved, err := ingestBrowserCrawlResult(c, meta, result)
						if err != nil {
							return err
						}
						ingestResult = &saved
					}
					switch strings.ToLower(strings.TrimSpace(c.String("format"))) {
					case "json":
						encoder := json.NewEncoder(c.App.Writer)
						encoder.SetIndent("", "  ")
						if ingestResult != nil {
							return encoder.Encode(browserCrawlOutput{
								Crawl:  result,
								Ingest: browserCrawlIngestOutput(*ingestResult),
							})
						}
						return encoder.Encode(result)
					case "table", "":
						if err := writeBrowserCrawlTable(c, result); err != nil {
							return err
						}
						if ingestResult != nil {
							fmt.Fprintf(c.App.Writer, "Stored ingest batch %s with %d event(s)\n", ingestResult.Batch.ExternalID, len(ingestResult.Events))
						}
						return nil
					default:
						return fmt.Errorf("unsupported output format %q", c.String("format"))
					}
				},
			},
		},
	}
}

type browserCrawlOutput struct {
	Crawl  collector.BrowserCrawlResult `json:"crawl"`
	Ingest browserCrawlIngestRecord     `json:"ingest"`
}

type browserCrawlIngestRecord struct {
	BatchID string `json:"batch_id"`
	Events  int    `json:"events"`
}

func browserCrawlIngestOutput(result hubapp.IngestEventsResult) browserCrawlIngestRecord {
	return browserCrawlIngestRecord{
		BatchID: result.Batch.ExternalID,
		Events:  len(result.Events),
	}
}

func ingestBrowserCrawlResult(c *urfavecli.Context, meta domain.AppMeta, result collector.BrowserCrawlResult) (hubapp.IngestEventsResult, error) {
	if err := requireBrowserIngestFlags(c); err != nil {
		return hubapp.IngestEventsResult{}, err
	}
	events := collector.BuildBrowserCrawlEvents(result, parseLabels(c.StringSlice("label")))
	if len(events) == 0 {
		return hubapp.IngestEventsResult{}, fmt.Errorf("browser crawl produced no ingest events")
	}

	container, cleanup, err := newDatabaseContainer(c.Context, meta)
	if err != nil {
		return hubapp.IngestEventsResult{}, err
	}
	defer cleanup()

	inputEvents := make([]hubapp.IngestEventInput, 0, len(events))
	for _, event := range events {
		inputEvents = append(inputEvents, hubapp.IngestEventInput{
			EventTime: event.EventTime,
			Type:      event.Type,
			Target:    event.Target,
			Severity:  event.Severity,
			Message:   event.Message,
			Region:    c.String("region"),
			Labels:    event.Labels,
			Payload:   event.Payload,
		})
	}
	return container.Hub.IngestEvents(c.Context, hubapp.IngestEventsInput{
		OrganizationSlug: c.String("org"),
		ProjectSlug:      c.String("project"),
		EnvironmentSlug:  c.String("env"),
		AppSlug:          c.String("app"),
		ServiceSlug:      c.String("service"),
		HostSlug:         c.String("host"),
		AgentID:          c.String("agent-id"),
		ExternalBatchID:  browserCrawlBatchID(c.String("batch-id"), result),
		Source:           "collector.browser",
		Region:           c.String("region"),
		Labels:           parseLabels(c.StringSlice("label")),
		Events:           inputEvents,
	})
}

func requireBrowserIngestFlags(c *urfavecli.Context) error {
	required := []string{"org", "project", "env", "host", "agent-id"}
	var missing []string
	for _, name := range required {
		if strings.TrimSpace(c.String(name)) == "" {
			missing = append(missing, "--"+name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%s required when --ingest is set", strings.Join(missing, ", "))
	}
	return nil
}

func browserCrawlBatchID(value string, result collector.BrowserCrawlResult) string {
	value = strings.TrimSpace(value)
	if value != "" {
		return value
	}
	timestamp := result.FinishedAt
	if timestamp.IsZero() {
		timestamp = time.Now().UTC()
	}
	return "browser-crawl-" + timestamp.UTC().Format("20060102T150405Z")
}

func writeBrowserCrawlTable(c *urfavecli.Context, result collector.BrowserCrawlResult) error {
	writer := tabwriter.NewWriter(c.App.Writer, 0, 0, 2, ' ', 0)
	fmt.Fprintln(writer, "PAGE\tMODE\tSTATUS\tSCRIPT\tTYPE\tDOMAIN\tSHA256/TAG\tURL")
	for _, page := range result.Pages {
		if len(page.Scripts) == 0 {
			fmt.Fprintf(writer, "%s\t%s\t%d\t-\t-\t-\t-\t%s\n", page.FinalURL, page.Mode, page.StatusCode, strings.Join(page.Warnings, "; "))
			continue
		}
		for index, script := range page.Scripts {
			pageLabel := page.FinalURL
			mode := page.Mode
			status := page.StatusCode
			if index > 0 {
				pageLabel = ""
				mode = ""
				status = 0
			}
			fmt.Fprintf(
				writer,
				"%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\n",
				pageLabel,
				mode,
				statusLabel(status),
				index+1,
				script.SourceType,
				script.Domain,
				scriptFingerprint(script),
				scriptDisplayURL(script),
			)
		}
		for _, warning := range page.Warnings {
			fmt.Fprintf(writer, "%s\t%s\tWARN\t-\t-\t-\t-\t%s\n", page.FinalURL, page.Mode, warning)
		}
	}
	return writer.Flush()
}

func statusLabel(status int) string {
	if status == 0 {
		return ""
	}
	return fmt.Sprintf("%d", status)
}

func scriptFingerprint(script collector.BrowserScriptObservation) string {
	if len(script.TagManagerIDs) > 0 {
		return strings.Join(script.TagManagerIDs, ",")
	}
	if script.SHA256 != "" {
		return shortHash(script.SHA256)
	}
	return ""
}

func scriptDisplayURL(script collector.BrowserScriptObservation) string {
	if script.URLRedacted != "" {
		return script.URLRedacted
	}
	return script.URL
}
