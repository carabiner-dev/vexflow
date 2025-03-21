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

	"github.com/carabiner-dev/vexflow/pkg/flow"
	"github.com/carabiner-dev/vexflow/pkg/scanner/osv"

	api "github.com/carabiner-dev/vexflow/pkg/api/v1"
)

type scanOptions struct {
	// repoOptions
	ClonePath string
}

// Validates the options in context with arguments
func (so *scanOptions) Validate() error {
	var errs = []error{}
	// if err := uo.repoOptions.Validate(); err != nil {
	// 	errs = append(errs, err)
	// }

	if so.ClonePath == "" {
		errs = append(errs, errors.New("path to code directory not set"))
	}

	return errors.Join(errs...)
}

// AddFlags adds the subcommands flags
func (so *scanOptions) AddFlags(cmd *cobra.Command) {
	// 	so.repoOptions.AddFlags(cmd)
	cmd.PersistentFlags().StringVar(
		&so.ClonePath, "clone-path", ".", "path top the codebase to scan",
	)
}

func addScan(parentCmd *cobra.Command) {
	opts := &scanOptions{}
	triageCommand := &cobra.Command{
		Short:             "list the vulnerabilities in a codebase as seen by the scanner",
		Use:               "scan",
		Example:           fmt.Sprintf(`%s scan --repo org/repo --branch=main `, appname),
		SilenceUsage:      false,
		SilenceErrors:     true,
		PersistentPreRunE: initLogging,
		PreRunE: func(_ *cobra.Command, args []string) error {
			if len(args) > 0 {
				if opts.ClonePath != "." && opts.ClonePath != "" && opts.ClonePath != args[0] {
					return errors.New("code directory specified twice")
				}
				opts.ClonePath = args[0]
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
				// Repository: fmt.Sprintf("github.com/%s/%s", org, repo),
				// Name:       opts.BranchName,
				ClonePath: opts.ClonePath,
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

			// You can also add tables row-by-row
			//t.Row("English", "You look absolutely fabulous.", "How's it going?")
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
