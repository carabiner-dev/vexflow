// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package flow

import (
	"bytes"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/carabiner-dev/ampel/pkg/attestation"
	"github.com/carabiner-dev/ampel/pkg/formats/predicate/generic"
	"github.com/carabiner-dev/ampel/pkg/formats/statement/intoto"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/google/uuid"
	gointoto "github.com/in-toto/attestation/go/v1"
	"github.com/openvex/go-vex/pkg/vex"
	"github.com/sirupsen/logrus"

	vexindex "github.com/carabiner-dev/vexflow/internal/index"
	api "github.com/carabiner-dev/vexflow/pkg/api/v1"
)

type managerImplementation interface {
	// CreateTriage starts a new triage. It will return an error if there is already
	// an equivalent triage not closed in the existing list.
	CreateTriage(api.TriageBackend, *api.Branch, *api.Vulnerability) (*api.Triage, error)

	// EnsureBranchClones reads a list of branches and ensures there is a local
	// clone of them.
	EnsureBranchClones(*Options, []*api.Branch) error

	// Scan vulnerabilities runs the configured scanner in the branch clone.
	// This function errors if the scan clone does not exist.
	ScanVulnerabilities(api.Scanner, *api.Branch) ([]*api.Vulnerability, error)

	// FetchBranchVexes fetches any available VEX docs for the branch
	FetchBranchVexes(api.VexPublisher, *api.Branch) ([]attestation.Envelope, error)

	// ExtractVexDocuments reads a list of attested VEX documents and extracts
	// the vex data.
	ExtractVexDocuments(*Options, []attestation.Envelope) ([]*vex.VEX, error)

	// SuppressVulnerabilities reads in the available VEX data and suppresses
	// the found vulnerabilities from the scanner findings.
	SuppressVulnerabilities(*Options, *api.Branch, []*vex.VEX, []*api.Vulnerability) ([]*api.Vulnerability, error)

	ListBranchTriages(api.TriageBackend, *api.Branch) ([]*api.Triage, error)
	ClassifyTriages([]*api.Triage) ([]*api.Triage, []*api.Triage, []*api.Triage)
	UpdateTriages([]*api.Triage, []*api.Triage) error

	FilterVulnerabilityTriages([]*api.Triage, *api.Vulnerability) ([]*api.Triage, error)

	// OpenNewTriages is the internal method used to create new triages. As opposed
	// to CreateTriage,  OpenNewTriages is used for autmated creation from scans
	// which means that it will never open a new triage process if one was opened
	// at any point.
	OpenNewTriages(api.TriageBackend, *api.Branch, []*api.Vulnerability, []*api.Triage) ([]*api.Triage, error)

	// TriagesToVexDocument converts a list of triages needing a statement to
	// a VEX document ready to publish to an attestations store.
	TriagesToVexDocument([]*api.Triage) (*vex.VEX, error)

	// TriagesToAttestation converts closed triages to an attestation
	TriagesToAttestation(triages []*api.Triage) (*intoto.Statement, error)

	// CloseRedundantTriages closes all triages for which a vulnerability is no
	// longer present, usually because the affected components were updated in the branch.
	CloseRedundantTriages(api.TriageBackend, []*api.Vulnerability, []*api.Triage) error

	// FilterApplicableStatements returns all statements applicable to the vulnerabilities
	FilterApplicableStatements([]*vex.VEX, []*api.Vulnerability) ([]*vex.Statement, error)

	BuildDocument(*Options, []*vex.Statement) (*vex.VEX, error)
}

type defaultImplementation struct{}

// CreateTriage creates a new triage in branch for the specified vulnerability.
// First, the function will check the existing list and if there is already one
// and not closed, it will return an error.
func (di *defaultImplementation) CreateTriage(backend api.TriageBackend, branch *api.Branch, vuln *api.Vulnerability) (*api.Triage, error) {
	// Get the list of triages
	triages, err := backend.ListBranchTriages(branch)
	if err != nil {
		return nil, err
	}

	// And filter those for the vulnerability
	existing, err := di.FilterVulnerabilityTriages(triages, vuln)
	if err != nil {
		return nil, fmt.Errorf("filtering existing vulnerability triages: %w", err)
	}
	for _, t := range existing {
		if t.Vulnerability.ID == vuln.ID &&
			t.Vulnerability.Component.Purl == vuln.ComponentPurl() &&
			t.Branch.Identifier() == branch.Identifier() {
			continue
		}
		if t.Status != api.StatusClosed {
			return nil, fmt.Errorf("unable to create a new triage process for %q, there is one already underway", vuln.ID)
		}
	}

	triage, err := backend.CreateTriage(branch, vuln)
	if err != nil {
		return nil, fmt.Errorf("opening triage process: %w", err)
	}
	return triage, nil
}

// EnsureBranchClones clones the repository and places HEAD at the last commit
// in the branch. For now, we can only clone fresh to a tmp directory. In the future
// we may support existing clones.
func (di *defaultImplementation) EnsureBranchClones(opts *Options, branches []*api.Branch) error {
	for _, branch := range branches {
		tmpDir, err := os.MkdirTemp("", "vexflow-tmpclone-")
		if err != nil {
			return fmt.Errorf("cloning repository: %w", err)
		}
		logrus.Infof("Cloning repo to %s", tmpDir)

		repoUrl := branch.Repository
		if opts.UseSSH {
			repoUrl = "git@github.com:" + strings.TrimPrefix(repoUrl, "github.com/")
		} else {
			repoUrl = "https://" + repoUrl
		}

		// Make a shallow clone of the repo to memory
		if _, err := git.PlainClone(tmpDir, false, &git.CloneOptions{
			URL:           repoUrl,
			ReferenceName: plumbing.NewBranchReferenceName(branch.Name),
			SingleBranch:  true,
			Depth:         1,
			// RecurseSubmodules: 0,
			// ShallowSubmodules: false,
		}); err != nil {
			return fmt.Errorf("cloning %q: %w", repoUrl, err)
		}
		branch.ClonePath = tmpDir
	}

	return nil
}

// ScanVulnerabilities scans the local clone of a branch and returns any found
// vulnerabilities.
func (di *defaultImplementation) ScanVulnerabilities(scanner api.Scanner, branch *api.Branch) ([]*api.Vulnerability, error) {
	if scanner == nil {
		return nil, fmt.Errorf("no scanner is configured")
	}
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
			if strings.HasPrefix(i, "CVE-") {
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

// ListBranchTriages returns all triages in the branch. For now this are all but
// at some point this will implement a cut out date to avoid reading all data.
func (di *defaultImplementation) ListBranchTriages(backend api.TriageBackend, branch *api.Branch) ([]*api.Triage, error) {
	triages, err := backend.ListBranchTriages(branch)
	if err != nil {
		return nil, err
	}
	return triages, nil
}

func (di *defaultImplementation) ClassifyTriages(triages []*api.Triage) (waitAssessment, waitStatement, waitClose []*api.Triage) {
	for _, t := range triages {
		if t.Status == api.StatusClosed {
			continue
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
		case api.StatusClosed:
			continue
		}
	}
	return waitAssessment, waitStatement, waitClose
}

func (di *defaultImplementation) UpdateTriages([]*api.Triage, []*api.Triage) error {
	return nil
}

// OpenNewTriages opens new triage processes for vulnerabilities found in the
// branch that don't have one already underway.
func (di *defaultImplementation) OpenNewTriages(backend api.TriageBackend, branch *api.Branch, vulns []*api.Vulnerability, existing []*api.Triage) ([]*api.Triage, error) {
	newTriages := []*api.Triage{}

	if len(vulns) == 0 {
		return newTriages, nil
	}
	// First, index the existing triage to find if there is one open alread
	vulnIndex := map[string]struct{}{}
	for _, t := range existing {
		key := fmt.Sprintf("%s::%s", t.Vulnerability.ID, t.Vulnerability.ComponentPurl())
		vulnIndex[key] = struct{}{}
	}

	for _, v := range vulns {
		if _, ok := vulnIndex[fmt.Sprintf("%s::%s", v.ID, v.ComponentPurl())]; !ok {
			// Create the new triage
			t, err := di.CreateTriage(backend, branch, v)
			if err != nil {
				return nil, fmt.Errorf("creating triage for %s: %w", v.ID, err)
			}
			newTriages = append(newTriages, t)
		}
	}
	return newTriages, nil
}

// TriagesToAttestation turns a list of triages into openvex documents and
// captures them in an attestation.
func (di *defaultImplementation) TriagesToAttestation(triages []*api.Triage) (*intoto.Statement, error) {
	doc, err := di.TriagesToVexDocument(triages)
	if err != nil {
		return nil, err
	}

	var b bytes.Buffer
	if err := doc.ToJSON(&b); err != nil {
		return nil, fmt.Errorf("rendering vex docs: %w", err)
	}
	predicate := &generic.Predicate{
		Type: attestation.PredicateType(vex.TypeURI),
		Data: b.Bytes(),
	}

	// Build the attestation subjects
	subjects := []*gointoto.ResourceDescriptor{}
	done := map[string]struct{}{}
	for _, t := range triages {
		if t.Status != api.StatusClosed && t.Status != api.StatusWaitingForStatement {
			return nil, fmt.Errorf("triage of vulnerability %s not ready to attest", t.Vulnerability.ID)
		}
		if _, ok := done[t.Branch.Identifier()]; ok {
			continue
		}
		subjects = append(subjects, t.Branch.ToResourceDescriptor())
	}
	return intoto.NewStatement(
		intoto.WithPredicate(predicate),
		intoto.WithSubject(subjects...),
	), nil
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

// CloseRedundantTriages closes all triages for which a vulnerability is no
// longer present, usually because the affected components were updated in the branch.
func (di *defaultImplementation) CloseRedundantTriages(backend api.TriageBackend, vulns []*api.Vulnerability, triages []*api.Triage) error {
	// Index the vulnerabilities and components
	vulnIndex := map[string]struct{}{}
	for _, v := range vulns {
		vulnIndex[fmt.Sprintf("%s::%s", v.ID, v.ComponentPurl())] = struct{}{}
	}

	// OK, now let's close all the triages for other vulns
	for _, t := range triages {
		// If the vulns is in the index, it is still in the codebase
		if _, ok := vulnIndex[fmt.Sprintf("%s::%s", t.Vulnerability.ID, t.Vulnerability.ComponentPurl())]; ok {
			continue
		}

		// Close the triage, posting a notice in the issue.
		if err := backend.CloseTriageWithMessage(
			t, fmt.Sprintf(
				"Latest scan of %s shows it is no longer in the %s branch. Closing.",
				t.Vulnerability.ID, t.Branch.Identifier(),
			),
		); err != nil {
			return err
		}
	}
	return nil
}

// FilterVulnerabilityTriages reads a list of triages and returns those for a specific vuln
func (di *defaultImplementation) FilterVulnerabilityTriages(triages []*api.Triage, vuln *api.Vulnerability) ([]*api.Triage, error) {
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

// FetchBranchVexes fetches any available VEX docs for the branch

func (di *defaultImplementation) FetchBranchVexes(publisher api.VexPublisher, branch *api.Branch) ([]attestation.Envelope, error) {
	atts, err := publisher.ReadBranchVEX(branch)
	if err != nil {
		return nil, fmt.Errorf("publisher error fetching attestations: %w", err)
	}
	return atts, nil
}

// SuppressVulnerabilities reads in the available VEX data and suppresses
// the found vulnerabilities from the scanner findings.
func (di *defaultImplementation) SuppressVulnerabilities(
	_ *Options, branch *api.Branch, vexes []*vex.VEX, vulns []*api.Vulnerability,
) ([]*api.Vulnerability, error) {
	return vulns, nil
}

// ExtractVexDocuments reads a list of attested VEX documents and extracts
// the vex data. At some point this function should validate the VEX
// signatures and authors
func (di *defaultImplementation) ExtractVexDocuments(_ *Options, attestations []attestation.Envelope) ([]*vex.VEX, error) {
	ret := []*vex.VEX{}
	for _, att := range attestations {
		if att.GetStatement() == nil {
			continue
		}

		pred := att.GetStatement().GetPredicate()
		if pred == nil {
			continue
		}

		doc, ok := att.GetStatement().GetPredicate().GetParsed().(*vex.VEX)
		if !ok {
			// Not a vex doc
			continue
		}
		ret = append(ret, doc)
	}
	return ret, nil
}

// FilterApplicableStatements gets all the VEX data for the branch and the
// vulnerabilitirs list detected by the scanner and returns the VEX statements
// that still matter. Those that don't (becasuse dependencies were upgraded
// or removed are ignored).
func (di *defaultImplementation) FilterApplicableStatements(docs []*vex.VEX, vulns []*api.Vulnerability) ([]*vex.Statement, error) {
	idx, err := vexindex.New(vexindex.WithDocument(docs...))
	if err != nil {
		return nil, fmt.Errorf("indexing documents: %w", err)
	}

	vexVulns := []*vex.Vulnerability{}
	for v := range vulns {
		vexVulns = append(vexVulns, vulns[v].ToVexVuln())
	}

	statements := idx.Matches(
		vexindex.WithVulnerabilities(vexVulns...),
	)

	// TODO(puerco): Here, we should have an option to generate affected
	// statements for any vuln that was not vexed.
	return statements, nil
}

func (di *defaultImplementation) BuildDocument(_ *Options, statements []*vex.Statement) (*vex.VEX, error) {
	doc := vex.New()
	if _, err := doc.GenerateCanonicalID(); err != nil {
		return nil, fmt.Errorf("generating doc ID: %w", err)
	}
	doc.Tooling = "http://github.com/carabiner-dev/vexflow"
	for _, s := range statements {
		doc.Statements = append(doc.Statements, *s)
	}
	return &doc, nil
}
