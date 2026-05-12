package cli

import (
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	hubapp "github.com/rcooler/aegrail/internal/hub"
	urfavecli "github.com/urfave/cli/v2"
)

func hubRulesCommand() *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "rules",
		Usage: "inspect Hub detection rule metadata",
		Subcommands: []*urfavecli.Command{
			{
				Name:  "list",
				Usage: "list registered detection rules",
				Flags: []urfavecli.Flag{
					&urfavecli.StringFlag{Name: "category", Usage: "optional category filter"},
					&urfavecli.StringFlag{Name: "platform", Usage: "optional platform filter"},
				},
				Action: func(c *urfavecli.Context) error {
					hub := hubapp.New(hubapp.Dependencies{})
					rules := filterRuleDefinitions(hub.ListRuleDefinitions(), c.String("category"), c.String("platform"))
					if len(rules) == 0 {
						fmt.Fprintln(c.App.Writer, "No rules found.")
						return nil
					}
					writer := tabwriter.NewWriter(c.App.Writer, 0, 0, 2, ' ', 0)
					fmt.Fprintln(writer, "ID\tVERSION\tCATEGORY\tPLATFORMS\tACTIONS")
					for _, rule := range rules {
						fmt.Fprintf(
							writer,
							"%s\t%s\t%s\t%s\t%s\n",
							rule.ID,
							rule.Version,
							rule.Category,
							strings.Join(rule.Platforms, ","),
							strings.Join(ruleActionHints(rule.ActionHints), ","),
						)
					}
					return writer.Flush()
				},
			},
			{
				Name:  "evaluate",
				Usage: "run built-in rule fixture evaluation sets",
				Flags: []urfavecli.Flag{
					&urfavecli.BoolFlag{Name: "fail-on-mismatch", Usage: "return a non-zero exit code when any fixture fails"},
				},
				Action: func(c *urfavecli.Context) error {
					summary := hubapp.EvaluateBuiltInRuleFixtures(time.Now().UTC())
					fmt.Fprintf(c.App.Writer, "Rule fixture evaluation: %d passed, %d failed, %d signal(s).\n", summary.Passed, summary.Failed, summary.Signals)

					writer := tabwriter.NewWriter(c.App.Writer, 0, 0, 2, ' ', 0)
					fmt.Fprintln(writer, "FIXTURE\tSTATUS\tEXPECTED\tACTUAL\tMISSING\tUNEXPECTED\tMISMATCHED")
					for _, result := range summary.Fixtures {
						status := "pass"
						if !result.Passed {
							status = "fail"
						}
						fmt.Fprintf(
							writer,
							"%s\t%s\t%d\t%d\t%d\t%d\t%d\n",
							result.Fixture.ID,
							status,
							len(result.Expected),
							len(result.Actual),
							len(result.Missing),
							len(result.Unexpected),
							len(result.Mismatched),
						)
					}
					if err := writer.Flush(); err != nil {
						return err
					}
					if summary.Failed > 0 {
						printRuleEvaluationFailures(c, summary)
						if c.Bool("fail-on-mismatch") {
							return fmt.Errorf("%d rule fixture(s) failed", summary.Failed)
						}
					}
					return nil
				},
			},
		},
	}
}

func filterRuleDefinitions(rules []hubapp.RuleDefinition, category string, platform string) []hubapp.RuleDefinition {
	category = strings.ToLower(strings.TrimSpace(category))
	platform = strings.ToLower(strings.TrimSpace(platform))
	filtered := make([]hubapp.RuleDefinition, 0, len(rules))
	for _, rule := range rules {
		if category != "" && string(rule.Category) != category {
			continue
		}
		if platform != "" && !rulePlatformsInclude(rule.Platforms, platform) {
			continue
		}
		filtered = append(filtered, rule)
	}
	return filtered
}

func rulePlatformsInclude(platforms []string, platform string) bool {
	for _, value := range platforms {
		if value == platform {
			return true
		}
	}
	return false
}

func ruleActionHints(actions []hubapp.RuleActionHint) []string {
	values := make([]string, 0, len(actions))
	for _, action := range actions {
		values = append(values, string(action))
	}
	return values
}

func printRuleEvaluationFailures(c *urfavecli.Context, summary hubapp.RuleEvaluationSummary) {
	for _, result := range summary.Fixtures {
		if result.Passed {
			continue
		}
		fmt.Fprintf(c.App.Writer, "\n%s failed:\n", result.Fixture.ID)
		for _, missing := range result.Missing {
			fmt.Fprintf(c.App.Writer, "  missing: %s severity=%s confidence=%s\n", missing.ID, missing.Severity, missing.Confidence)
		}
		for _, unexpected := range result.Unexpected {
			fmt.Fprintf(c.App.Writer, "  unexpected: %s severity=%s confidence=%s\n", unexpected.ID, unexpected.Severity, unexpected.Confidence)
		}
		for _, mismatch := range result.Mismatched {
			fmt.Fprintf(
				c.App.Writer,
				"  mismatch: %s severity %s->%s confidence %s->%s\n",
				mismatch.ID,
				mismatch.ExpectedSeverity,
				mismatch.ActualSeverity,
				mismatch.ExpectedConfidence,
				mismatch.ActualConfidence,
			)
		}
	}
}
