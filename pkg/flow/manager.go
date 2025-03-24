// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package flow

import (
	"errors"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"

	api "github.com/carabiner-dev/vexflow/pkg/api/v1"
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

type Options struct {
	UseSSH bool
}

// Manager is the main object. It handles the lifecycle of a vulnerability's
// impact on a project
type Manager struct {
	Options       Options
	impl          managerImplementation
	Branches      []*api.Branch
	scanner       api.Scanner
	triageBackend api.TriageBackend
	publisher     api.VexPublisher
}

// CreateTriage opens a new triage process a vulnerability in the specified branch
func (mgr *Manager) CreateTriage(branch *api.Branch, vuln *api.Vulnerability) (*api.Triage, error) {
	return mgr.impl.CreateTriage(mgr.triageBackend, branch, vuln)
}

// deleteTempClones removes the temporary data from the cloned branches
func deleteTempClones(branches []*api.Branch) {
	for _, b := range branches {
		if b.ClonePath != "" {
			if err := os.RemoveAll(b.ClonePath); err != nil {
				logrus.Error(err)
			}
		}
	}
}

// UpdateBranchFlowWithScan updates the flows open at the repository and creates
// new ones based on the latest vulnerability reports available.
func (mgr *Manager) UpdateBranchFlowWithScan(branch *api.Branch) error {
	// Ensure clones
	if err := mgr.impl.EnsureBranchClones(&mgr.Options, []*api.Branch{branch}); err != nil {
		return fmt.Errorf("ensuring up to date clones: %w", err)
	}
	defer deleteTempClones([]*api.Branch{branch})

	// Extract current vulnerabilities
	vulns, err := mgr.impl.ScanVulnerabilities(mgr.scanner, branch)
	if err != nil {
		return fmt.Errorf("checking for vulnerabilities: %w", err)
	}

	logrus.Infof("%d vulnerabilities found in branch", len(vulns))

	triages, err := mgr.impl.ListBranchTriages(mgr.triageBackend, branch)
	if err != nil {
		return fmt.Errorf("listing open triage processes: %w", err)
	}

	// Update the open triage cases
	newTriages, err := mgr.impl.OpenNewTriages(mgr.triageBackend, branch, vulns, triages)
	if err != nil {
		return fmt.Errorf("opening new triage processes: %w", err)
	}

	// TODO(puerco): Here any vulns that disappeared that have a triage
	// need to be closed.

	logrus.Infof("Created %d new triage processes for new vulnerabilities", len(newTriages))

	waitAssessment, waitStatement, waitClose := mgr.impl.ClassifyTriages(triages)
	logrus.Infof(
		"Triage Status: [%d+%d To Assess] [%d To VEX] [%d To Close]",
		len(waitAssessment), len(newTriages), len(waitStatement), len(waitClose),
	)

	if err := mgr.impl.CloseRedundantTriages(mgr.triageBackend, vulns, waitAssessment); err != nil {
		return fmt.Errorf("closing redundant triages: %w", err)
	}

	if err := mgr.PublishStatements(waitStatement); err != nil {
		return fmt.Errorf("publishing statements: %w", err)
	}

	if err := mgr.CloseOpenTriages(waitClose); err != nil {
		return fmt.Errorf("closing completed triages: %w", err)
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

func (mgr *Manager) UpdateBranchFlow(branch *api.Branch) error {
	triages, err := mgr.triageBackend.ListBranchTriages(branch)
	if err != nil {
		return err
	}

	// Classify the triages depending on their status
	waitClose, waitStatement, waitAssessment := mgr.impl.ClassifyTriages(triages)
	logrus.Infof(
		"Triage Status: [%d To Assess] [%d To VEX] [%d To Close]",
		len(waitAssessment), len(waitStatement), len(waitClose),
	)

	if err := mgr.PublishStatements(waitStatement); err != nil {
		return fmt.Errorf("publishing statements: %w", err)
	}

	if err := mgr.CloseOpenTriages(waitClose); err != nil {
		return fmt.Errorf("closing completed triages: %w", err)
	}

	return nil
}

func (mgr *Manager) CloseOpenTriages(triages []*api.Triage) error {
	errs := []error{}
	for _, t := range triages {
		if err := mgr.triageBackend.CloseTriage(t); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// PublishStatements generates the VEX documents for the open triages
// and releases them using the configured publisher.
func (mgr *Manager) PublishStatements(triages []*api.Triage) error {
	// No triages, noop.
	if len(triages) == 0 {
		return nil
	}

	statement, err := mgr.impl.TriagesToAttestation(triages)
	if err != nil {
		return fmt.Errorf("generating VEX document: %w", err)
	}

	// Publish the document using the configured publisher
	notice, err := mgr.publisher.PublishAttestation(statement)
	if err != nil {
		return fmt.Errorf("publishing document: %w", err)
	}

	errs := []error{}
	for _, t := range triages {
		if err := mgr.triageBackend.AppendPublishNotice(t, notice); err != nil {
			errs = append(errs, err)
			continue
		}

		// Close the triage now that the notice is published
		if err := mgr.triageBackend.CloseTriage(t); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

func (m *Manager) ScanBranchCode(branch *api.Branch) ([]*api.Vulnerability, error) {
	return m.impl.ScanVulnerabilities(m.scanner, branch)
}
