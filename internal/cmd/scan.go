// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
	"github.com/spf13/cobra"

	api "github.com/carabiner-dev/vexflow/pkg/api/v1"
	"github.com/carabiner-dev/vexflow/pkg/flow"
	"github.com/carabiner-dev/vexflow/pkg/scanner/osv"
)

type scanPathOptions struct {
	Path string
}

// Validates the options in context with arguments
func (so *scanPathOptions) Validate() error {
	errs := []error{}
	if so.Path == "" {
		errs = append(errs, errors.New("path to code directory not set"))
	}

	return errors.Join(errs...)
}

// AddFlags adds the subcommands flags
func (so *scanPathOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(
		&so.Path, "path", ".", "path top the codebase to scan",
	)
}

func addScan(parentCmd *cobra.Command) {
	scanCommand := &cobra.Command{
		Short:        "list the vulnerabilities the configured scanner sees",
		Use:          "scan [path|repo] scanning/target",
		SilenceUsage: false,
		Long: `
vexflow scan [path|repo]: List vulnerabilities found by the configured scanner.

The can command invokes the configured scanner and returns the vulnerabilities
it sees in a codebase. scan has two subcommands:

vexflow scan path /path/to/code

Calls the scanner in a local codebase, returning the vulnerability list.

vexflow scan repo github.com/organization/repository

The repo subcommand works like path but clones the repository from the
remote URL and runs the scanner in the local copy.

By default vexflow scan outputs its findings to a table on STDOUT. The results
can also be output in the OSV format optionally wrapped in an attestation.

`,
	}
	addScanPath(scanCommand)
	parentCmd.AddCommand(scanCommand)
}

func addScanPath(parentCmd *cobra.Command) {
	opts := &scanPathOptions{}
	triageCommand := &cobra.Command{
		Short:             "list the vulnerabilities in a local codebase as seen by the scanner",
		Use:               "path",
		Example:           fmt.Sprintf(`%s scan --repo org/repo --branch=main `, appname),
		SilenceUsage:      false,
		SilenceErrors:     true,
		PersistentPreRunE: initLogging,
		PreRunE: func(_ *cobra.Command, args []string) error {
			if len(args) > 0 {
				if opts.Path != "." && opts.Path != "" && opts.Path != args[0] {
					return errors.New("code directory specified twice")
				}
				opts.Path = args[0]
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			// Validate the options
			if err := opts.Validate(); err != nil {
				return err
			}

			mgr, err := flow.New(
				flow.WithScanner(osv.New()),
			)
			if err != nil {
				return err
			}

			branch := &api.Branch{
				ClonePath: opts.Path,
			}

			vulns, err := mgr.ScanBranchCode(branch)
			if err != nil {
				return err
			}

			t := table.New().
				Border(lipgloss.NormalBorder()).
				BorderStyle(lipgloss.NewStyle().Foreground(purple)).
				StyleFunc(func(row, col int) lipgloss.Style {
					switch {
					case row == table.HeaderRow:
						return headerStyle
					case row%2 == 0:
						return evenRowStyle
					default:
						return oddRowStyle
					}
				}).
				Headers("VULNERABILITY", "ALIASES", "COMPONENT")

			for _, vuln := range vulns {
				t.Row(
					vuln.ID,
					strings.Join(vuln.Aliases, "\n"),
					vuln.ComponentPurl(),
				)
			}

			fmt.Println(t)
			return nil
		},
	}
	opts.AddFlags(triageCommand)
	parentCmd.AddCommand(triageCommand)
}
