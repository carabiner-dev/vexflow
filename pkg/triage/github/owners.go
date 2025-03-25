// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package github

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/carabiner-dev/vcslocator"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

type Owners struct {
	Approvers         []string          `json:"approvers"          yaml:"approvers"`
	Reviewers         []string          `json:"reviewers"          yaml:"reviewers"`
	EmeritusApprovers []string          `json:"emeritus_approvers" yaml:"emeritus_approvers"`
	Alias             map[string]string `json:"aliases"            yaml:"aliases"`
}

// ReadOwners fetches the owners file from your github repo
func (th *TriageHandler) ReadOwners() error {
	if th.options.Org == "" || th.options.Repo == "" {
		return fmt.Errorf("unable to get owners data, org or repo not set")
	}

	locator := fmt.Sprintf("git+https://github.com/%s/%s#OWNERS", th.options.Org, th.options.Repo)
	var b bytes.Buffer
	logrus.Debugf("Fetching owners data from %s", locator)

	if err := vcslocator.CopyFile(locator, &b); err != nil {
		// If we got an error because there is no owners file, then don't
		// fail, we can work with the empty allowlist.
		if !strings.Contains(err.Error(), "file does not exist") {
			return fmt.Errorf("reading repo data: %w", err)
		}
		b.WriteString("approvers: []\n")
	}

	owners, err := parseOwnersData(&b)
	if err != nil {
		return fmt.Errorf("parsing owners data: %w", err)
	}
	logrus.Debugf("Owners file parsed:\n%v", owners)

	th.Owners = owners
	return nil
}

// parseOwnersData parses owners data file from the reader at r
func parseOwnersData(r io.Reader) (*Owners, error) {
	dec := yaml.NewDecoder(r)
	owners := &Owners{}
	if err := dec.Decode(owners); err != nil {
		return nil, fmt.Errorf("parsing owners data: %w", err)
	}
	return owners, nil
}
