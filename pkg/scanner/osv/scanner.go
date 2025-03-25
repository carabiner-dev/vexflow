// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package osv

import (
	"errors"
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

type Scanner struct{}

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
	logrus.Debugf("OSV: Scanning %s", branch.ClonePath)
	scannerAction := osvscanner.ScannerActions{
		DirectoryPaths: []string{branch.ClonePath},
	}

	vulnResult, err := osvscanner.DoScan(scannerAction)
	if err != nil && !errors.Is(err, osvscanner.ErrVulnerabilitiesFound) {
		return nil, fmt.Errorf("scanning source: %w", err)
	}
	return &vulnResult, nil
}

func (s *Scanner) ingestScanResults(results *models.VulnerabilityResults) ([]*api.Vulnerability, error) {
	ret := []*api.Vulnerability{}
	for _, result := range results.Results {
		for i := range result.Packages {
			pkg, err := osvPackageToPackage(&result.Packages[i].Package)
			if err != nil {
				return nil, fmt.Errorf("converting package: %w", err)
			}

			for j := range result.Packages[i].Vulnerabilities {
				// Build the aliases list
				aliases := []string{}
				id := ""
				for _, alias := range result.Packages[i].Vulnerabilities[j].Aliases {
					if strings.HasPrefix(alias, "CVE-") && id == "" {
						id = alias
						continue
					}
					aliases = append(aliases, alias)
				}

				if id == "" {
					id = result.Packages[i].Vulnerabilities[i].ID
				} else {
					aliases = append(aliases, result.Packages[i].Vulnerabilities[j].ID)
				}
				ret = append(ret, &api.Vulnerability{
					ID:        id,
					Aliases:   aliases,
					Summary:   result.Packages[i].Vulnerabilities[j].Summary,
					Details:   result.Packages[i].Vulnerabilities[j].Details,
					Component: pkg,
				})
			}
		}
	}
	return ret, nil
}

func osvPackageToPackage(opkg *models.PackageInfo) (*api.Package, error) {
	var ptype string
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
