// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package dir

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	ampel "github.com/carabiner-dev/ampel/pkg/attestation"
	"github.com/openvex/go-vex/pkg/vex"
	"github.com/sirupsen/logrus"

	api "github.com/carabiner-dev/vexflow/pkg/api/v1"
)

type Publisher struct {
	Path string
}

// PublishDocument writes the vex document to a directory
func (p *Publisher) PublishDocument(doc *vex.VEX) (*api.StatementNotice, error) {
	if doc.ID == "" {
		return nil, fmt.Errorf("VEX document has no ID set")
	}

	if p.Path == "" {
		return nil, fmt.Errorf("directory publisher has no path set")
	}

	products := []string{}
	for i := range doc.Statements {
		for _, p := range doc.Statements[i].Products {
			if j, ok := p.Hashes[vex.SHA256]; ok {
				if !slices.Contains(products, string(j)) {
					products = append(products, string(j))
				}
			}
		}
	}
	if len(products) == 0 {
		return nil, fmt.Errorf("no product found in vex document")
	}

	if len(products) > 1 {
		return nil, fmt.Errorf("vex document has information about more than one product")
	}

	// Open the file
	dirName := filepath.Join(p.Path, products[0])
	if err := os.MkdirAll(dirName, os.FileMode(0o755)); err != nil {
		return nil, fmt.Errorf("creating output directory: %w", err)
	}
	path := filepath.Join(dirName, fmt.Sprintf("%s.openvex.json", doc.ID))

	f, err := os.Create(path) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("opening vex document file: %w", err)
	}
	defer f.Close() //nolint:errcheck

	if err := doc.ToJSON(f); err != nil {
		return nil, fmt.Errorf("writing vex data: %w", err)
	}
	logrus.Debugf("VEX data written to %s", path)
	return &api.StatementNotice{
		Published: time.Now(),
		Location:  "file:" + path,
	}, nil
}

func (p *Publisher) PublishAttestation(att ampel.Statement) (*api.StatementNotice, error) {
	return nil, fmt.Errorf("PublishAttestation not yet implemented")
}

func (p *Publisher) ReadBranchVEX(branch *api.Branch) ([]ampel.Envelope, error) {
	return nil, fmt.Errorf("read vex from dirs not yet implemented")
}
