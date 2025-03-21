// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package flow

import (
	"slices"
	"strings"

	api "github.com/carabiner-dev/vexflow/pkg/api/v1"
	"github.com/google/uuid"
	"github.com/openvex/go-vex/pkg/vex"
)

type managerImplementation interface {
	EnsureBranchClones([]*api.Branch) error
	ScanVulnerabilities(api.Scanner, *api.Branch) ([]*api.Vulnerability, error)
	ListBranchTriages(*api.Branch) ([]*api.Triage, error)
	ClassifyTriages([]*api.Vulnerability, []*api.Triage) ([]*api.Vulnerability, []*api.Triage, []*api.Triage, error)
	UpdateTriages([]*api.Triage, []*api.Triage) error
	// OpenNewTriages(*api.Branch, []*api.Vulnerability) ([]*api.Triage, error)
	OpenNewTriages(*api.Branch, []*api.Vulnerability) ([]*api.Triage, error)

	// TriagesToVexDocument converts a list of triages needing a statement to
	// a VEX document ready to publish to an attestations store.
	TriagesToVexDocument([]*api.Triage) (*vex.VEX, error)
}

type defaultImplementation struct{}

func (di *defaultImplementation) EnsureBranchClones([]*api.Branch) error {
	return nil
}

func (di *defaultImplementation) ScanVulnerabilities(scanner api.Scanner, branch *api.Branch) ([]*api.Vulnerability, error) {
	vulns, err := scanner.GetBranchVulnerabilities(branch)
	if err != nil {
		return nil, err
	}
	return di.dedupeVulns(vulns), nil
}

func (di *defaultImplementation) dedupeVulns(vulns []*api.Vulnerability) []*api.Vulnerability {
	index := map[string]*api.Vulnerability{}
	for _, v := range vulns {
		id := v.ID
		aliases := []string{}
		if !slices.Contains(aliases, id) {
			aliases = append(aliases, id)
		}
		for _, i := range v.Aliases {
			if strings.HasPrefix("CVE-", id) {
				id = i
			}
			if !slices.Contains(aliases, i) {
				aliases = append(aliases, i)
			}
		}
		key := strings.Join([]string{id, v.ComponentPurl()}, "::")
		if _, ok := index[key]; !ok {
			index[key] = &api.Vulnerability{
				ID:        id,
				Aliases:   aliases,
				Summary:   v.Summary,
				Details:   v.Details,
				Component: v.Component,
			}
			continue
		}

		// If we have one, then we augment if
		for _, i := range aliases {
			if !slices.Contains(index[key].Aliases, i) {
				index[key].Aliases = append(index[key].Aliases, i)
			}
		}
	}

	ret := []*api.Vulnerability{}
	for _, v := range index {
		ret = append(ret, v)
	}

	return ret
}

func (di *defaultImplementation) ListBranchTriages(*api.Branch) ([]*api.Triage, error) {
	return nil, nil
}

func (di *defaultImplementation) ClassifyTriages([]*api.Vulnerability, []*api.Triage) ([]*api.Vulnerability, []*api.Triage, []*api.Triage, error) {
	return nil, nil, nil, nil
}
func (di *defaultImplementation) UpdateTriages([]*api.Triage, []*api.Triage) error {
	return nil
}

// OpenNewTriages(*api.Branch, []*api.Vulnerability) ([]*api.Triage, error)
func (di *defaultImplementation) OpenNewTriages(*api.Branch, []*api.Vulnerability) ([]*api.Triage, error) {
	return nil, nil
}

func (di *defaultImplementation) TriagesToVexDocument(triages []*api.Triage) (*vex.VEX, error) {
	statements := []vex.Statement{}
	for _, t := range triages {
		if t.Status != api.StatusWaitingForStatement {
			continue
		}

		// Get the last slash command
		cmd := t.LastCommand()
		if cmd == nil {
			// Or continue if its not here (why not?)
			continue
		}

		impactStatement := ""
		actionStatement := ""
		if cmd.VexStatus() == vex.StatusNotAffected {
			impactStatement = cmd.Blurb
		} else if cmd.VexStatus() == vex.StatusAffected {
			actionStatement = cmd.Blurb
		}

		s := vex.Statement{
			ID:            "urn:uuid:" + uuid.NewString(),
			Vulnerability: *t.Vulnerability.ToVex(),
			Timestamp:     &cmd.Date,
			Products: []vex.Product{
				{
					Component: *t.Branch.ToVexComponent(),
					Subcomponents: []vex.Subcomponent{
						{Component: *t.Vulnerability.VexComponent()},
					},
				},
			},
			Status:          cmd.VexStatus(),
			Justification:   cmd.VexJustification(),
			ImpactStatement: impactStatement,
			ActionStatement: actionStatement,
		}
		statements = append(statements, s)
	}

	doc := vex.New()
	doc.ID = "urn:uuid:" + uuid.NewString()
	doc.Statements = statements
	return &doc, nil
}
