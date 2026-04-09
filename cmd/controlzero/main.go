// Command controlzero is the CLI for the Go SDK.
//
//	controlzero init           Write a sample policy.yaml
//	controlzero validate       Lint your policy file
//	controlzero test <tool>    Dry-run a tool call against the policy
//	controlzero tail           Print the local audit log
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"controlzero.ai/sdk/go"
	"controlzero.ai/sdk/go/templates"
	"github.com/spf13/cobra"
)

const Version = "0.1.0"

func main() {
	root := &cobra.Command{
		Use:   "controlzero",
		Short: "ControlZero: AI agent governance, policies, and audit",
		Long: `ControlZero: AI agent governance, policies, and audit.

Get started in 30 seconds:

  controlzero init           Write a sample policy.yaml
  controlzero validate       Lint your policy file
  controlzero test <tool>    Dry-run a tool call against the policy
  controlzero tail           Print the local audit log`,
		Version: Version,
	}

	root.AddCommand(initCmd())
	root.AddCommand(validateCmd())
	root.AddCommand(testCmd())
	root.AddCommand(tailCmd())

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func initCmd() *cobra.Command {
	var template, out string
	var force bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Write a sample policy file with examples and comments",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !contains(templates.Names, template) {
				return fmt.Errorf("unknown template %q. Valid: %s",
					template, strings.Join(templates.Names, ", "))
			}
			if _, err := os.Stat(out); err == nil && !force {
				return fmt.Errorf("%s already exists. Use --force to overwrite", out)
			}
			data, err := templates.FS.ReadFile(template + ".yaml")
			if err != nil {
				return fmt.Errorf("template not found: %w", err)
			}
			if err := os.WriteFile(out, data, 0o644); err != nil {
				return err
			}
			fmt.Printf("Wrote %s (%s template)\n\n", out, template)
			fmt.Println("Next steps:")
			fmt.Printf("  1. Open %s and edit the rules to fit your app\n", out)
			fmt.Printf("  2. Run: controlzero validate %s\n", out)
			fmt.Printf("  3. Test: controlzero test delete_file --policy %s\n", out)
			fmt.Printf("  4. Use it in code: controlzero.New(controlzero.WithPolicyFile(%q))\n", out)
			return nil
		},
	}
	cmd.Flags().StringVarP(&template, "template", "t", "generic",
		fmt.Sprintf("Template name. One of: %s", strings.Join(templates.Names, ", ")))
	cmd.Flags().StringVarP(&out, "out", "o", "controlzero.yaml", "Output file path")
	cmd.Flags().BoolVarP(&force, "force", "f", false, "Overwrite existing file")
	return cmd
}

func validateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate [policy_file]",
		Short: "Validate a policy file. Exits non-zero on errors.",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := "controlzero.yaml"
			if len(args) > 0 {
				path = args[0]
			}
			if _, err := os.Stat(path); err != nil {
				return fmt.Errorf("%s not found", path)
			}
			rules, err := controlzero.LoadPolicy(path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "INVALID: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("OK: %s parsed cleanly (%d rules)\n", path, len(rules))
			for _, r := range rules {
				idTag := ""
				if r.ID != "" {
					idTag = "(" + r.ID + ")"
				}
				fmt.Printf("  - %-5s %v %s\n", r.Effect, r.Actions, idTag)
			}
			return nil
		},
	}
}

func testCmd() *cobra.Command {
	var method, policy, argsJSON string
	cmd := &cobra.Command{
		Use:   "test <tool>",
		Short: "Dry-run a single tool call against a policy file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, cmdArgs []string) error {
			tool := cmdArgs[0]

			var argsMap map[string]any
			if err := json.Unmarshal([]byte(argsJSON), &argsMap); err != nil {
				fmt.Fprintf(os.Stderr, "error: --args is not valid JSON: %v\n", err)
				os.Exit(2)
			}

			cz, err := controlzero.New(controlzero.WithPolicyFile(policy))
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
			defer cz.Close()

			decision, _ := cz.Guard(tool, controlzero.GuardOptions{
				Args:   argsMap,
				Method: method,
			})

			fmt.Printf("tool:    %s\n", tool)
			fmt.Printf("method:  %s\n", method)
			fmt.Printf("args:    %v\n", argsMap)
			fmt.Println()
			fmt.Printf("DECISION: %s\n", strings.ToUpper(decision.Effect))
			if decision.PolicyID != "" {
				fmt.Printf("matched: %s\n", decision.PolicyID)
			}
			if decision.Reason != "" {
				fmt.Printf("reason:  %s\n", decision.Reason)
			}
			if decision.Allowed() {
				os.Exit(0)
			}
			os.Exit(3)
			return nil
		},
	}
	cmd.Flags().StringVarP(&method, "method", "m", "*", "Method name (default '*')")
	cmd.Flags().StringVarP(&policy, "policy", "p", "controlzero.yaml", "Policy file")
	cmd.Flags().StringVarP(&argsJSON, "args", "a", "{}", "Tool args as a JSON string")
	return cmd
}

func tailCmd() *cobra.Command {
	var logPath string
	var lines int
	cmd := &cobra.Command{
		Use:   "tail",
		Short: "Print the last N lines of the local audit log",
		RunE: func(cmd *cobra.Command, args []string) error {
			f, err := os.Open(logPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: log file not found: %s\n", logPath)
				fmt.Fprintln(os.Stderr,
					"hint: run a Guard() call first, or pass --log to a different path.")
				os.Exit(1)
			}
			defer f.Close()
			data, _ := io.ReadAll(f)
			all := strings.Split(string(data), "\n")
			start := len(all) - lines
			if start < 0 {
				start = 0
			}
			for _, line := range all[start:] {
				if line != "" {
					fmt.Println(line)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&logPath, "log", "l", "./controlzero.log", "Log file path")
	cmd.Flags().IntVarP(&lines, "lines", "n", 10, "Show the last N lines")
	return cmd
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
