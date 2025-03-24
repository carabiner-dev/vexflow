// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package osvcmdline

import (
	"fmt"
	"strings"

	cosv "github.com/carabiner-dev/osv/go/osv"
	"sigs.k8s.io/release-utils/command"

	api "github.com/carabiner-dev/vexflow/pkg/api/v1"
)

func New() *Scanner {
	return &Scanner{}
}

type Scanner struct{}

func (s *Scanner) GetBranchVulnerabilities(branch *api.Branch) ([]*api.Vulnerability, error) {
	return s.scanBranch(branch)
}

func (s *Scanner) scanBranch(branch *api.Branch) ([]*api.Vulnerability, error) {
	if branch.ClonePath == "" {
		return nil, fmt.Errorf("no local clone defined in branch")
	}
	cmd := command.NewWithWorkDir(branch.ClonePath, "osv-scanner", "scan", "--format=json", branch.ClonePath)
	output, err := cmd.RunSilentSuccessOutput()
	if err != nil {
		return nil, fmt.Errorf("running scanner: %w", err)
	}

	return processOSVreport(output.Output())
}

func processOSVreport(data string) ([]*api.Vulnerability, error) {
	// Create new parser
	parser := cosv.NewParser()

	// Parse the OSV data
	results, err := parser.ParseRestultsFromStream(strings.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("parsing osvx results: %w", err)
	}
	ret := []*api.Vulnerability{}
	for _, r := range results.Results {
		for _, p := range r.Packages {
			pkg, err := osvPackageToPackage(p.Package)
			if err != nil {
				return nil, fmt.Errorf("error creating package")
			}

			for i := range p.Vulnerabilities {
				// Build the aliases list
				aliases := []string{}
				id := ""
				for _, alias := range p.Vulnerabilities[i].Aliases {
					if strings.HasPrefix(alias, "CVE-") && id == "" {
						id = alias
						continue
					}
					aliases = append(aliases, alias)
				}

				if id == "" {
					id = p.Vulnerabilities[i].Id
				} else {
					aliases = append(aliases, p.Vulnerabilities[i].Id)
				}
				ret = append(ret, &api.Vulnerability{
					ID:        id,
					Aliases:   aliases,
					Summary:   p.Vulnerabilities[i].Summary,
					Details:   p.Vulnerabilities[i].Details,
					Component: pkg,
				})
			}
		}
	}

	return ret, nil
}

func osvPackageToPackage(opkg *cosv.Result_Package_Info) (*api.Package, error) {
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
