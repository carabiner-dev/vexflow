// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package github

type fnOption = func(*TriageHandler) error

type Options struct {
	// Org/Repo where VexFlow will store the triage processes
	Org  string
	Repo string

	// Labels
	LabelAffected           string
	LabelNotAffected        string
	LabelFixed              string
	LabelUnderInvestigation string
}

func WithTriageOrg(org string) fnOption {
	return func(th *TriageHandler) error {
		th.options.Org = org
		return nil
	}
}

func WithTriageRepo(repo string) fnOption {
	return func(th *TriageHandler) error {
		th.options.Repo = repo
		return nil
	}
}
