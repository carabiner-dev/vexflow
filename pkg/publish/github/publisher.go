// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package github

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	ampel "github.com/carabiner-dev/ampel/pkg/attestation"
	"github.com/carabiner-dev/bnd/pkg/bnd"
	"github.com/carabiner-dev/bnd/pkg/upload"
	"google.golang.org/protobuf/encoding/protojson"

	api "github.com/carabiner-dev/vexflow/pkg/api/v1"
	"github.com/openvex/go-vex/pkg/vex"
)

func New(funcs ...fnOpt) (*Publisher, error) {
	p := &Publisher{
		Options: Options{},
	}
	for _, fn := range funcs {
		if err := fn(p); err != nil {
			return nil, err
		}
	}
	return p, nil
}

type fnOpt func(*Publisher) error

func WithOrg(org string) fnOpt {
	return func(p *Publisher) error {
		p.Options.Org = org
		return nil
	}
}

func WithRepo(repo string) fnOpt {
	return func(p *Publisher) error {
		p.Options.Repo = repo
		return nil
	}
}

type Publisher struct {
	Options Options
}

type Options struct {
	Repo string
	Org  string
}

func (p *Publisher) PublishDocument(doc *vex.VEX) (*api.StatementNotice, error) {
	return nil, fmt.Errorf("PublishDocument not yet implemented")
}

// PublishAttestation pushes an attestes VEX document to the GitHub attestations
// store configured in the uploader.
func (p *Publisher) PublishAttestation(att ampel.Statement) (*api.StatementNotice, error) {
	signer := bnd.NewSigner()
	data, err := json.Marshal(att)
	if err != nil {
		return nil, fmt.Errorf("marshaling attestation: %w", err)
	}
	bundle, err := signer.SignStatement(data)
	if err != nil {
		return nil, fmt.Errorf("signing statement: %w", err)
	}

	// Marshal the bundle to JS
	bundleData, err := protojson.Marshal(bundle)
	if err != nil {
		return nil, fmt.Errorf("marshaling signed bundle: %w", err)
	}

	os.WriteFile("/tmp/vex.bundle.json", bundleData, os.FileMode(0o644))

	// First, sign the attestation
	uploader := upload.NewClient()
	if err := uploader.PushBundleToGithub(p.Options.Org, p.Options.Repo, bundleData); err != nil {
		return nil, fmt.Errorf("pushing signed bundle to GitHub: %w", err)
	}

	return &api.StatementNotice{
		Published: time.Now(),
		Location:  fmt.Sprintf("github.com/%s/%s", p.Options.Org, p.Options.Repo),
	}, nil
}
