// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package flow

import (
	"fmt"
	"os"

	api "github.com/carabiner-dev/vexflow/pkg/api/v1"
	"github.com/sirupsen/logrus"
)

// New creates a new flow manager
func New(fn ...initFunc) (*Manager, error) {
	manager := &Manager{
		impl:          &defaultImplementation{},
		Branches:      []*api.Branch{},
		scanner:       nil,
		triageBackend: nil,
	}

	for _, f := range fn {
		if err := f(manager); err != nil {
			return nil, err
		}
	}
	return manager, nil
}

// Manager is the main object. It handles the lifecycle of a vulnerability's
// impact on a project
type Manager struct {
	impl          managerImplementation
	Branches      []*api.Branch
	scanner       api.Scanner
	triageBackend api.TriageBackend
}

func (mgr *Manager) CreateTriage(branch *api.Branch, vuln *api.Vulnerability) (*api.Triage, error) {
	existing, err := mgr.GetVulnerabilityTriages(branch, vuln)
	if err != nil {
		return nil, fmt.Errorf("checking open triages: %w", err)
	}

	for _, t := range existing {
		if t.Status != api.StatusClosed {
			return nil, fmt.Errorf("unable to create a new triage process for %q, there is one already underway", vuln.ID)
		}
	}

	triage, err := mgr.triageBackend.CreateTriage(branch, vuln)
	if err != nil {
		return nil, fmt.Errorf("opening triage process: %w", err)
	}
	return triage, nil
}

// UpdateBranchFlowWithScan updates the flows open at the repository and creates
// new ones based on the latest vulnerability reports available.
func (mgr *Manager) UpdateBranchFlowWithScan(branch *api.Branch) error {
	// Ensure clones
	if err := mgr.impl.EnsureBranchClones(mgr.Branches); err != nil {
		return fmt.Errorf("ensuring up to date clones: %w", err)
	}

	// Extract current vulnerabilities
	vulns, err := mgr.impl.ScanVulnerabilities(mgr.scanner, branch)
	if err != nil {
		return fmt.Errorf("checking for vulnerabilities: %w", err)
	}

	triages, err := mgr.impl.ListBranchTriages(branch)
	if err != nil {
		return fmt.Errorf("listing open triage processes: %w", err)
	}

	missing, opens, closed, err := mgr.impl.ClassifyTriages(vulns, triages)
	if err != nil {
		return fmt.Errorf("classifying triage processes: %w", err)
	}

	if err := mgr.impl.UpdateTriages(opens, closed); err != nil {
		return fmt.Errorf("updating ongoing triage processes: %w", err)
	}

	// Update the open triage cases
	if _, err := mgr.impl.OpenNewTriages(branch, missing); err != nil {
		return fmt.Errorf("opening new triage processes: %w", err)
	}

	return nil
}

func (mgr *Manager) ListBranchTriages(branch *api.Branch) ([]*api.Triage, error) {
	return mgr.triageBackend.ListBranchTriages(branch)
}

func (mgr *Manager) ListOpenBranchTriages(branch *api.Branch) ([]*api.Triage, error) {
	triages, err := mgr.triageBackend.ListBranchTriages(branch)
	if err != nil {
		return nil, err
	}

	ret := []*api.Triage{}
	for _, t := range triages {
		if t.Status != api.StatusClosed {
			ret = append(ret, t)
		}
	}

	return ret, nil
}

// GetVulnerabilityTriages
func (mgr *Manager) GetVulnerabilityTriages(branch *api.Branch, vuln *api.Vulnerability) ([]*api.Triage, error) {
	triages, err := mgr.ListBranchTriages(branch)
	if err != nil {
		return nil, err
	}

	ret := []*api.Triage{}
	var triagePurl, vulnPurl string
	if vuln.Component != nil {
		vulnPurl = vuln.Component.Purl
	}

	for _, t := range triages {
		if t.Vulnerability.Component != nil {
			triagePurl = t.Vulnerability.Component.Purl
		}

		if t.Vulnerability.HasId(vuln.ID) && triagePurl == vulnPurl {
			ret = append(ret, t)
		}
	}
	return ret, nil
}

func (mgr *Manager) UpdateBranchFlow(branch *api.Branch) error {
	triages, err := mgr.triageBackend.ListBranchTriages(branch)
	if err != nil {
		return err
	}

	// Classify the triages depending on their status
	var waitClose, waitStatement, waitAssessment []*api.Triage

	for _, t := range triages {
		if t.Status == api.StatusClosed {
			continue
		}

		// Update the triage details
		if err := mgr.triageBackend.ReadTriageStatus(t); err != nil {
			return fmt.Errorf("updating triage from API: %w", err)
		}

		switch t.Status {
		case api.StatusWaitingForAsessment:
			logrus.Infof("%s (%s) is waiting for maintainer assessment", t.Vulnerability.ID, t.Vulnerability.ComponentPurl())
			waitAssessment = append(waitAssessment, t)
		case api.StatusWaitingForStatement:
			logrus.Infof("%s (%s) is waiting for satatement to be published", t.Vulnerability.ID, t.Vulnerability.ComponentPurl())
			waitStatement = append(waitStatement, t)
		case api.StatusWaitingForClose:
			logrus.Infof("%s (%s) is waiting for issue to be closed", t.Vulnerability.ID, t.Vulnerability.ComponentPurl())
			waitClose = append(waitClose, t)
		}
	}

	if err := mgr.PublishStatements(waitStatement); err != nil {
		return fmt.Errorf("publishing statements: %w", err)
	}

	return nil
}

func (mgr *Manager) PublishStatements(triages []*api.Triage) error {
	doc, err := mgr.impl.TriagesToVexDocument(triages)
	if err != nil {
		return fmt.Errorf("generating VEX document: %w", err)
	}

	return doc.ToJSON(os.Stdout)
}
