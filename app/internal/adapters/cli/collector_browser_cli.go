package cli

import (
	"encoding/json"
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/rcooler/aegrail/internal/collector"
	"github.com/rcooler/aegrail/internal/domain"
	urfavecli "github.com/urfave/cli/v2"
)

func collectorBrowserCommand(meta domain.AppMeta) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "browser",
		Usage: "crawl rendered-page-adjacent browser evidence",
		Subcommands: []*urfavecli.Command{
			{
				Name:  "crawl",
				Usage: "crawl pages and inventory scripts from initial HTML",
				Flags: []urfavecli.Flag{
					&urfavecli.StringSliceFlag{Name: "url", Aliases: []string{"u"}, Required: true, Usage: "page URL to crawl; repeat for multiple pages"},
					&urfavecli.IntFlag{Name: "max-pages", Value: 10, Usage: "maximum supplied URLs to crawl"},
					&urfavecli.DurationFlag{Name: "timeout", Value: 15 * time.Second, Usage: "per-page HTTP timeout"},
					&urfavecli.StringFlag{Name: "user-agent", Usage: "override crawler User-Agent"},
					&urfavecli.BoolFlag{Name: "same-host-only", Usage: "skip supplied URLs outside the seed host set"},
					&urfavecli.StringFlag{Name: "format", Value: "table", Usage: "output format: table or json"},
				},
				Action: func(c *urfavecli.Context) error {
					runtime := collector.NewRuntime(collector.Config{Name: "browser"})
					result, err := runtime.CrawlBrowserPages(c.Context, collector.BrowserCrawlInput{
						URLs:         c.StringSlice("url"),
						MaxPages:     c.Int("max-pages"),
						Timeout:      c.Duration("timeout"),
						UserAgent:    c.String("user-agent"),
						SameHostOnly: c.Bool("same-host-only"),
					})
					if err != nil {
						return err
					}
					switch strings.ToLower(strings.TrimSpace(c.String("format"))) {
					case "json":
						encoder := json.NewEncoder(c.App.Writer)
						encoder.SetIndent("", "  ")
						return encoder.Encode(result)
					case "table", "":
						return writeBrowserCrawlTable(c, result)
					default:
						return fmt.Errorf("unsupported output format %q", c.String("format"))
					}
				},
			},
		},
	}
}

func writeBrowserCrawlTable(c *urfavecli.Context, result collector.BrowserCrawlResult) error {
	writer := tabwriter.NewWriter(c.App.Writer, 0, 0, 2, ' ', 0)
	fmt.Fprintln(writer, "PAGE\tSTATUS\tSCRIPT\tTYPE\tDOMAIN\tSHA256/TAG\tURL")
	for _, page := range result.Pages {
		if len(page.Scripts) == 0 {
			fmt.Fprintf(writer, "%s\t%d\t-\t-\t-\t-\t%s\n", page.FinalURL, page.StatusCode, strings.Join(page.Warnings, "; "))
			continue
		}
		for index, script := range page.Scripts {
			pageLabel := page.FinalURL
			status := page.StatusCode
			if index > 0 {
				pageLabel = ""
				status = 0
			}
			fmt.Fprintf(
				writer,
				"%s\t%s\t%d\t%s\t%s\t%s\t%s\n",
				pageLabel,
				statusLabel(status),
				index+1,
				script.SourceType,
				script.Domain,
				scriptFingerprint(script),
				scriptDisplayURL(script),
			)
		}
		for _, warning := range page.Warnings {
			fmt.Fprintf(writer, "%s\tWARN\t-\t-\t-\t-\t%s\n", page.FinalURL, warning)
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
