// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	api "github.com/carabiner-dev/vexflow/pkg/api/v1"
	"github.com/carabiner-dev/vexflow/pkg/flow"
	"github.com/carabiner-dev/vexflow/pkg/publish/dir"
	ghpublish "github.com/carabiner-dev/vexflow/pkg/publish/github"
	"github.com/carabiner-dev/vexflow/pkg/scanner/osv"
	"github.com/carabiner-dev/vexflow/pkg/triage/github"
)

type updateOptions struct {
	repoOptions
	scan        bool
	publishPath string
}

// Validates the options in context with arguments
func (uo *updateOptions) Validate() error {
	errs := []error{}
	if err := uo.repoOptions.Validate(); err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

// AddFlags adds the subcommands flags
func (to *updateOptions) AddFlags(cmd *cobra.Command) {
	to.repoOptions.AddFlags(cmd)
	cmd.PersistentFlags().StringVar(
		&to.publishPath, "publish-path", "", "location to publish VEX documents",
	)
	cmd.PersistentFlags().BoolVar(
		&to.scan, "scan", true, "clone the repo and scan for new vulnerabilities",
	)
}

func (to *updateOptions) GetBackendRepo() (backendOrg, backendRepo string, err error) {
	// By default we collect data from .vexflow
	if to.TriageRepo == DefaultBackendRepo {
		org, _, err := github.ParseSlug(to.RepoSlug)
		if err != nil {
			return "", "", fmt.Errorf("parsing repo slug: %w", err)
		}
		backendOrg = org
		backendRepo = DefaultBackendRepo
	} else {
		org, repo, err := github.ParseSlug(to.TriageRepo)
		if err != nil {
			return "", "", fmt.Errorf("parsing triage repo slug: %w", err)
		}
		backendOrg = org
		backendRepo = repo
	}

	return backendOrg, backendRepo, nil
}

func addUpdate(parentCmd *cobra.Command) {
	opts := &updateOptions{}
	triageCommand := &cobra.Command{
		Short:             "updates all open triage processes running for the branch",
		Use:               "update",
		Example:           fmt.Sprintf(`%s update --repo org/repo --branch=main `, appname),
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

			// Create the statement publisher:
			var publisher api.VexPublisher

			// If there is a publish path, we use it. Otherwise we will publish
			// to the github attestations store to the same repo where the triage
			// is going on.
			if opts.publishPath != "" {
				publisher = &dir.Publisher{
					Path: strings.TrimPrefix(opts.publishPath, "file:"),
				}
			} else {
				publisher, err = ghpublish.New(
					ghpublish.WithOrg(backendOrg),
					ghpublish.WithRepo(backendRepo),
				)
				if err != nil {
					return err
				}
			}

			// Create the flow manager
			mgr, err := flow.New(
				flow.WithBackend(backend),
				flow.WithScanner(osv.New()),
				flow.WithPublisher(publisher),
				flow.WithSSH(opts.UseSSH),
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

			// Only clone and scan if set in the options
			if opts.scan {
				return mgr.UpdateBranchFlowWithScan(branch)
			}
			return mgr.UpdateBranchFlow(branch)
		},
	}
	opts.AddFlags(triageCommand)
	parentCmd.AddCommand(triageCommand)
}
