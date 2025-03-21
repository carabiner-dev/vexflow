// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"

	"github.com/carabiner-dev/vexflow/pkg/triage/github"
	"github.com/spf13/cobra"
)

type repoOptions struct {
	BranchName string
	RepoSlug   string
	TriageRepo string
	UseSSH     bool
}

func (to *repoOptions) GetBackendRepo() (string, string, error) {
	backendOrg := ""
	backendRepo := ""

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

func (ro *repoOptions) Validate() error {
	errs := []error{}
	if ro.BranchName == "" {
		errs = append(errs, errors.New("branch name not set"))
	}
	if ro.RepoSlug == "" {
		errs = append(errs, errors.New("repository slug (repo/name) not set "))
	} else if _, _, err := github.ParseSlug(ro.RepoSlug); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (to *repoOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVarP(
		&to.BranchName, "branch", "b", "main", "name of the branch to triage",
	)
	cmd.PersistentFlags().StringVarP(
		&to.RepoSlug, "repo", "r", "", "code repository (slug org/name)",
	)

	cmd.PersistentFlags().StringVar(
		&to.TriageRepo, "triage-repo", DefaultBackendRepo, "backend repository to store triage data (slug org/repo)",
	)
	cmd.PersistentFlags().BoolVar(
		&to.UseSSH, "ssh", false, "use SSH when cloning",
	)
}
