// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/carabiner-dev/vexflow/pkg/flow"
	"github.com/carabiner-dev/vexflow/pkg/scanner/osv"
	"github.com/carabiner-dev/vexflow/pkg/triage/github"

	api "github.com/carabiner-dev/vexflow/pkg/api/v1"
)

const DefaultBackendRepo = ".vexflow"

type triageOptions struct {
	repoOptions
	Vulnerability string
	Component     string
}

// Validates the options in context with arguments
func (to *triageOptions) Validate() error {
	errs := []error{}
	if err := to.repoOptions.Validate(); err != nil {
		errs = append(errs, err)
	}

	if to.Vulnerability == "" {
		errs = append(errs, errors.New("no vulnerability defined"))
	}

	if to.Component == "" {
		errs = append(errs, errors.New("component not defined"))
	}

	return errors.Join(errs...)
}

// AddFlags adds the subcommands flags
func (to *triageOptions) AddFlags(cmd *cobra.Command) {
	to.repoOptions.AddFlags(cmd)
	cmd.PersistentFlags().StringVarP(
		&to.Vulnerability, "vulnerability", "v", "", "vulnerability to triage",
	)

	cmd.PersistentFlags().StringVarP(
		&to.Component, "component", "c", "", "component where the vulnerability is found (purl)",
	)
}

func addTriage(parentCmd *cobra.Command) {
	opts := &triageOptions{}
	triageCommand := &cobra.Command{
		Short:             "starts a new triage process for a branch repo",
		Use:               "triage",
		Example:           fmt.Sprintf(`%s triage --repo org/repo --branch=main --vuln=CVE-1234-56789`, appname),
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
				flow.WithScanner(osv.New()),
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

			pkg := &api.Package{}
			if err := pkg.SetPurl(opts.Component); err != nil {
				return err
			}

			triage, err := mgr.CreateTriage(branch, &api.Vulnerability{
				ID:        opts.Vulnerability,
				Component: pkg,
			})
			if err != nil {
				return err
			}

			fmt.Printf("%+v", triage)

			return nil
		},
	}
	opts.AddFlags(triageCommand)
	parentCmd.AddCommand(triageCommand)
}
