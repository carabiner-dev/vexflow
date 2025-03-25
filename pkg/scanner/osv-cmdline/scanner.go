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
	for _, r := range results.GetResults() {
		for _, p := range r.GetPackages() {
			pkg, err := osvPackageToPackage(p.GetPackage())
			if err != nil {
				return nil, fmt.Errorf("error creating package")
			}

			for i := range p.GetVulnerabilities() {
				// Build the aliases list
				aliases := []string{}
				id := ""
				for _, alias := range p.GetVulnerabilities()[i].GetAliases() {
					if strings.HasPrefix(alias, "CVE-") && id == "" {
						id = alias
						continue
					}
					aliases = append(aliases, alias)
				}

				if id == "" {
					id = p.GetVulnerabilities()[i].GetId()
				} else {
					aliases = append(aliases, p.GetVulnerabilities()[i].GetId())
				}
				ret = append(ret, &api.Vulnerability{
					ID:        id,
					Aliases:   aliases,
					Summary:   p.GetVulnerabilities()[i].GetDetails(),
					Details:   p.GetVulnerabilities()[i].GetSummary(),
					Component: pkg,
				})
			}
		}
	}

	return ret, nil
}

func osvPackageToPackage(opkg *cosv.Result_Package_Info) (*api.Package, error) {
	var ptype string
	switch opkg.GetEcosystem() {
	case "Go":
		ptype = "golang"
	default:
		return nil, fmt.Errorf("unknown package ecosystem %s", opkg.GetEcosystem())
	}

	return &api.Package{
		Type:    ptype,
		Name:    opkg.GetName(),
		Version: opkg.GetVersion(),
		Purl:    fmt.Sprintf("pkg:%s/%s@%v", ptype, opkg.GetName(), opkg.GetVersion()),
	}, nil
}
