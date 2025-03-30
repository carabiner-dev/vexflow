// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package flow

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/carabiner-dev/ampel/pkg/attestation"
	"github.com/carabiner-dev/ampel/pkg/formats/predicate/generic"
	aosv "github.com/carabiner-dev/ampel/pkg/formats/predicate/osv"
	"github.com/carabiner-dev/ampel/pkg/formats/statement/intoto"
	"github.com/carabiner-dev/osv/go/osv"
	"github.com/go-git/go-git/v5"
	gointoto "github.com/in-toto/attestation/go/v1"
	"github.com/openvex/go-vex/pkg/vex"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

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

	// Fetch branch vexes for any vulnerabilities found
	vexAttestations, err := mgr.impl.FetchBranchVexes(mgr.publisher, branch)
	if err != nil {
		return fmt.Errorf("fetching VEX data: %w", err)
	}
	logrus.Infof("%d preexisting VEX documents found", len(vexAttestations))

	vexes, err := mgr.impl.ExtractVexDocuments(&mgr.Options, vexAttestations)
	if err != nil {
		return fmt.Errorf("extracting VEX data: %w", err)
	}

	// Suppress any open vulns with the VEX data:
	vulns, err = mgr.impl.SuppressVulnerabilities(&mgr.Options, branch, vexes, vulns)
	if err != nil {
		return fmt.Errorf("suppressing vulnerabilities: %w", err)
	}
	logrus.Infof("%d vulnerabilities after suppressing with VEX", len(vulns))

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

// VulnsToAttestation reads a list of vulnerabilities and generates a
func (m *Manager) VulnsToAttestation(subject *gointoto.ResourceDescriptor, vulns []*api.Vulnerability) (attestation.Statement, error) {
	osvResults, err := m.VulnsToOSV(vulns)
	if err != nil {
		return nil, fmt.Errorf("generating OSV report: %w", err)
	}

	osvResults.Results[0].Source = &osv.Result_Source{
		Path: subject.GetUri(),
		Type: "repository",
	}

	// Marshal the json output here
	osvJSON, err := protojson.Marshal(osvResults)
	if err != nil {
		return nil, fmt.Errorf("marshaling json data: %w", err)
	}

	predicate := &generic.Predicate{
		Type:          aosv.PredicateType,
		Parsed:        osvResults,
		Data:          osvJSON,
		Verifications: []*attestation.SignatureVerification{},
	}

	s := intoto.NewStatement(
		intoto.WithSubject(subject),
		intoto.WithPredicate(predicate),
	)

	return s, nil
}

// VulnsToOSV reads a list of vulnerabilities and returns a list of results
// formateed in the results set from OSV scanner. Note that this only creates
// the list, the results origin does not get populated.
func (m *Manager) VulnsToOSV(vulns []*api.Vulnerability) (*osv.Results, error) {
	results := osv.Results{
		Date: timestamppb.Now(),
		Results: []*osv.Result{
			{
				Packages: []*osv.Result_Package{},
			},
		},
	}

	pmap := map[string]*osv.Result_Package{}

	for _, v := range vulns {
		key := v.Component.Type + "::" + v.Component.Name

		// If we haven't seen this package, add an entry to the map
		if _, ok := pmap[key]; !ok {
			pmap[key] = &osv.Result_Package{
				Package: &osv.Result_Package_Info{
					Name:      v.Component.Name,
					Version:   v.Component.Version,
					Ecosystem: v.Component.Type,
				},
				Vulnerabilities: []*osv.Record{},
			}
		}

		// Add the vuln recors
		rec := &osv.Record{
			SchemaVersion: osv.Version,
			Id:            v.ID,
			// Modified:         &timestamppb.Timestamp{},
			// Published:        &timestamppb.Timestamp{},
			// Withdrawn:        &timestamppb.Timestamp{},
			Aliases: v.Aliases,
			Summary: v.Summary,
			Details: v.Details,
			// Severity:         []*osv.Severity{},
			Affected: []*osv.Affected{
				{
					Versions: []string{v.Component.Version},
					Package: &osv.Package{
						Ecosystem: v.Component.Type,
						Name:      v.Component.Name,
						Purl:      v.ComponentPurl(),
					},
				},
			},
		}
		pmap[key].Vulnerabilities = append(pmap[key].Vulnerabilities, rec)
	}

	for _, packageVulns := range pmap {
		results.Results[0].Packages = append(results.Results[0].Packages, packageVulns)
	}

	return &results, nil
}

// LocalRepoToResourceDescriptor reads a local repository and returns the
func (m *Manager) LocalRepoToResourceDescriptor(path string) (*gointoto.ResourceDescriptor, error) {
	url, err := getLocalRepoRemoteURL(path)
	if err != nil {
		return nil, fmt.Errorf("reading remote: %w", err)
	}

	branchName, err := getLocalRepoBranch(path)
	if err != nil {
		return nil, fmt.Errorf("reading repo branch: %w", err)
	}

	// Normalize the URL
	url = strings.TrimSuffix(url, ".git")
	if strings.HasPrefix(url, "git@") {
		url = strings.Replace(url, ":", "/", 1)
		url = strings.TrimPrefix(url, "git@")
	}
	url = strings.TrimPrefix(url, "https://")

	branch := &api.Branch{
		Repository: url,
		Name:       branchName,
		ClonePath:  path,
	}

	return branch.ToResourceDescriptor(), nil
}

func getLocalRepoBranch(path string) (string, error) {
	repo, err := git.PlainOpen(path)
	if err != nil {
		return "", fmt.Errorf("opening local repository: %w", err)
	}
	head, err := repo.Head()
	if err != nil {
		return "", err
	}

	return head.Name().Short(), nil
}

// getLocalRepoRemoteURL reads a local repo clone and tries to guess
// the url of the main remote
func getLocalRepoRemoteURL(path string) (string, error) {
	repo, err := git.PlainOpen(path)
	if err != nil {
		return "", fmt.Errorf("opening local repository: %w", err)
	}
	remotes, err := repo.Remotes()
	if err != nil {
		return "", fmt.Errorf("reading repo remotes: %w", err)
	}
	if len(remotes) == 0 {
		p, err := filepath.Abs(path)
		if err != nil {
			return "", fmt.Errorf("computing path: %w", err)
		}
		return "file:" + p, nil
	}
	var remoteUrl, firstUrl string
	for _, remote := range remotes {
		if remote.Config() == nil {
			continue
		}
		if len(remote.Config().URLs) == 0 {
			continue
		}

		if firstUrl == "" {
			firstUrl = remote.Config().URLs[0]
		}
		if remote.Config().Name == "origin" && remoteUrl == "" {
			remoteUrl = remote.Config().URLs[0]
		}
		if remote.Config().Name == "upstream" {
			remoteUrl = remote.Config().URLs[0]
		}
	}
	if remoteUrl == "" {
		remoteUrl = firstUrl
	}
	return remoteUrl, nil
}

// ScanRemoteBranch clones a remote repo, scans for vulnerabilities and remove
// the local copy
func (mgr *Manager) ScanRemoteBranch(branch *api.Branch) ([]*api.Vulnerability, error) {
	// Ensure clones
	if err := mgr.impl.EnsureBranchClones(&mgr.Options, []*api.Branch{branch}); err != nil {
		return nil, fmt.Errorf("ensuring up to date clones: %w", err)
	}
	defer deleteTempClones([]*api.Branch{branch})

	// Extract current vulnerabilities
	vulns, err := mgr.impl.ScanVulnerabilities(mgr.scanner, branch)
	if err != nil {
		return nil, fmt.Errorf("checking for vulnerabilities: %w", err)
	}
	return vulns, nil
}

// AssembleBranchDocument gathers all VEX data applicable to vulnerabilities
// present in the branch. This is intended to be run at build time, to compile
// all exploitability data for the project.
func (mgr *Manager) AssembleBranchDocument(branch *api.Branch) (*vex.VEX, error) {
	// Ensure clones
	if err := mgr.impl.EnsureBranchClones(&mgr.Options, []*api.Branch{branch}); err != nil {
		return nil, fmt.Errorf("ensuring up to date clones: %w", err)
	}
	defer deleteTempClones([]*api.Branch{branch})

	// Extract current vulnerabilities
	vulns, err := mgr.impl.ScanVulnerabilities(mgr.scanner, branch)
	if err != nil {
		return nil, fmt.Errorf("checking for vulnerabilities: %w", err)
	}
	logrus.Infof("%d vulnerabilities found in branch", len(vulns))

	// Fetch branch vexes for any vulnerabilities found
	vexAttestations, err := mgr.impl.FetchBranchVexes(mgr.publisher, branch)
	if err != nil {
		return nil, fmt.Errorf("fetching VEX data: %w", err)
	}
	logrus.Infof("%d preexisting VEX documents found", len(vexAttestations))

	vexes, err := mgr.impl.ExtractVexDocuments(&mgr.Options, vexAttestations)
	if err != nil {
		return nil, fmt.Errorf("extracting VEX data: %w", err)
	}

	statements, err := mgr.impl.FilterApplicableStatements(vexes, vulns)
	if err != nil {
		return nil, fmt.Errorf("filtering statements: %w", err)
	}

	doc, err := mgr.impl.BuildDocument(&mgr.Options, statements)
	if err != nil {
		return doc, fmt.Errorf("building document: %w", err)
	}
	return doc, nil
}
