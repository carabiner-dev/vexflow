// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
	"github.com/spf13/cobra"

	api "github.com/carabiner-dev/vexflow/pkg/api/v1"
	"github.com/carabiner-dev/vexflow/pkg/flow"
	"github.com/carabiner-dev/vexflow/pkg/triage/github"
)

var (
	purple    = lipgloss.Color("99")
	gray      = lipgloss.Color("245")
	lightGray = lipgloss.Color("241")

	headerStyle  = lipgloss.NewStyle().Foreground(purple).Bold(true).Align(lipgloss.Center)
	cellStyle    = lipgloss.NewStyle().Padding(0, 3)
	oddRowStyle  = cellStyle.Foreground(gray)
	evenRowStyle = cellStyle.Foreground(lightGray)
)

type lsOptions struct {
	repoOptions
}

// Validates the options in context with arguments
func (lo *lsOptions) Validate() error {
	errs := []error{}
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
			if len(args) > 0 {
				if opts.RepoSlug != "" && opts.RepoSlug != args[0] {
					return fmt.Errorf("repository specified twice")
				}
				opts.RepoSlug = args[0]
			}
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

			// Init the github backend to the triage repository
			backend, err := github.New(
				github.WithTriageOrg(backendOrg),
				github.WithTriageRepo(backendRepo),
			)
			if err != nil {
				return fmt.Errorf("creating github backend: %w", err)
			}

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
			branch := &api.Branch{
				Repository: fmt.Sprintf("github.com/%s/%s", org, repo),
				Name:       opts.BranchName,
			}
			triages, err := mgr.ListOpenBranchTriages(branch)
			if err != nil {
				return err
			}

			if len(triages) == 0 {
				fmt.Printf("\n✅ No open triages found in %s\n", branch.Identifier())
				return nil
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
				Headers("REPOSITORY", "BRANCH", "VULNERABILITY", "STATUS")

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
