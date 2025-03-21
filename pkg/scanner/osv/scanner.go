// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package osv

import (
	"fmt"
	"strings"

	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/google/osv-scanner/v2/pkg/osvscanner"
	"github.com/sirupsen/logrus"

	api "github.com/carabiner-dev/vexflow/pkg/api/v1"
)

func New() *Scanner {
	return &Scanner{}
}

type Scanner struct {
}

func (s *Scanner) GetBranchVulnerabilities(branch *api.Branch) ([]*api.Vulnerability, error) {
	logrus.Infof("Scanning %s", branch.ClonePath)
	results, err := s.scanBranch(branch)
	if err != nil {
		return nil, err
	}

	vulns, err := s.ingestScanResults(results)
	if err != nil {
		return nil, fmt.Errorf("ingesting results: %w", err)
	}
	return vulns, nil
}

func (s *Scanner) scanBranch(branch *api.Branch) (*models.VulnerabilityResults, error) {
	// if !util.Exists(branch.ClonePath) {
	// 	return nil, fmt.Errorf("unable to scan branch, local clone not found")
	// }
	logrus.Infof("Scanning %s", branch.ClonePath)
	scannerAction := osvscanner.ScannerActions{
		// LockfilePaths:              context.StringSlice("lockfile"),
		// SBOMPaths:                  context.StringSlice("sbom"),
		// Recursive:                  context.Bool("recursive"),
		// IncludeGitRoot:             context.Bool("include-git-root"),
		// NoIgnore:                   context.Bool("no-ignore"),
		// ConfigOverridePath:         context.String("config"),
		DirectoryPaths: []string{branch.ClonePath},
		// CallAnalysisStates:         callAnalysisStates,
		// ExperimentalScannerActions: experimentalScannerActions,
	}

	vulnResult, err := osvscanner.DoScan(scannerAction)
	if err != nil {
		return nil, fmt.Errorf("scanning source: %w", err)
	}
	return &vulnResult, nil
}

func (s *Scanner) ingestScanResults(results *models.VulnerabilityResults) ([]*api.Vulnerability, error) {
	ret := []*api.Vulnerability{}
	for _, result := range results.Results {
		for _, pkgvulns := range result.Packages {
			pkg, err := osvPackageToPackage(&pkgvulns.Package)
			if err != nil {
				return nil, fmt.Errorf("converting package: %w", err)
			}

			for _, osvvuln := range pkgvulns.Vulnerabilities {
				// Build the aliases list
				aliases := []string{}
				id := ""
				for _, alias := range osvvuln.Aliases {
					if strings.HasPrefix(alias, "CVE-") && id == "" {
						id = alias
						continue
					}
					aliases = append(aliases, alias)
				}

				if id == "" {
					id = osvvuln.ID
				} else {
					aliases = append(aliases, osvvuln.ID)
				}
				ret = append(ret, &api.Vulnerability{
					ID:        id,
					Aliases:   aliases,
					Summary:   osvvuln.Summary,
					Details:   osvvuln.Details,
					Component: pkg,
				})
			}
		}
	}
	return ret, nil
}

func osvPackageToPackage(opkg *models.PackageInfo) (*api.Package, error) {
	ptype := ""
	switch opkg.Ecosystem {
	case "Go":
		ptype = "golang"
	default:
		return nil, fmt.Errorf("unknown package ecosystem %s", opkg.Ecosystem)
	}

	return &api.Package{
		Type:    ptype,
		Name:    opkg.Name,
		Version: opkg.Version,
		Purl:    fmt.Sprintf("pkg:%s/%s@%v", ptype, opkg.Name, opkg.Version),
	}, nil
}
