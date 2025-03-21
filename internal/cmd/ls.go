// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"

	"github.com/carabiner-dev/vexflow/pkg/flow"
	"github.com/carabiner-dev/vexflow/pkg/triage/github"

	api "github.com/carabiner-dev/vexflow/pkg/api/v1"
)

type lsOptions struct {
	repoOptions
}

// Validates the options in context with arguments
func (lo *lsOptions) Validate() error {
	var errs = []error{}
	if err := lo.repoOptions.Validate(); err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

// AddFlags adds the subcommands flags
func (lo *lsOptions) AddFlags(cmd *cobra.Command) {
	lo.repoOptions.AddFlags(cmd)

}

func addLs(parentCmd *cobra.Command) {
	opts := &lsOptions{}
	triageCommand := &cobra.Command{
		Short:             "list the ongoing triage processes",
		Use:               "ls",
		Example:           fmt.Sprintf(`%s ls --repo org/repo --branch=main `, appname),
		SilenceUsage:      false,
		SilenceErrors:     true,
		PersistentPreRunE: initLogging,
		PreRunE: func(_ *cobra.Command, args []string) error {
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			// Validate the options
			if err := opts.Validate(); err != nil {
				return err
			}

			backendOrg, backendRepo, err := opts.GetBackendRepo()
			if err != nil {
				return err
			}

			backend, err := github.New()
			if err != nil {
				return fmt.Errorf("creating github backend: %w", err)
			}

			backend.Options.Org = backendOrg
			backend.Options.Repo = backendRepo

			mgr, err := flow.New(
				flow.WithBackend(backend),
			)
			if err != nil {
				return err
			}

			org, repo, err := github.ParseSlug(opts.RepoSlug)
			if err != nil {
				return err
			}

			triages, err := mgr.ListOpenBranchTriages(&api.Branch{
				Repository: fmt.Sprintf("github.com/%s/%s", org, repo),
				Name:       opts.BranchName,
			})
			if err != nil {
				return err
			}

			purple := lipgloss.Color("99")
			gray := lipgloss.Color("245")
			lightGray := lipgloss.Color("241")

			headerStyle := lipgloss.NewStyle().Foreground(purple).Bold(true).Align(lipgloss.Center)
			cellStyle := lipgloss.NewStyle().Padding(0, 3) //.Width(14)
			oddRowStyle := cellStyle.Foreground(gray)
			evenRowStyle := cellStyle.Foreground(lightGray)

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
				Headers("REPOSITORY", "BRANCH", "VULNERABILITY", "STATUS")

			// You can also add tables row-by-row
			//t.Row("English", "You look absolutely fabulous.", "How's it going?")
			for _, triage := range triages {
				t.Row(
					triage.Branch.Repository, triage.Branch.Name,
					triage.Vulnerability.ID, string(triage.Status),
				)
			}

			fmt.Println(t)

			return nil
		},
	}
	opts.AddFlags(triageCommand)
	parentCmd.AddCommand(triageCommand)
}
