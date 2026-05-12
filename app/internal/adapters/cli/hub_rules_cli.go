package cli

import (
	"fmt"
	"strings"
	"text/tabwriter"

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
