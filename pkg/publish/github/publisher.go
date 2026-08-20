// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/carabiner-dev/attestation"
	"github.com/carabiner-dev/collector"
	bundleenv "github.com/carabiner-dev/collector/envelope/bundle"
	"github.com/carabiner-dev/collector/filters"
	cdgh "github.com/carabiner-dev/collector/repository/github"
	"github.com/carabiner-dev/signer"
	"github.com/openvex/go-vex/pkg/vex"
	"google.golang.org/protobuf/proto"

	api "github.com/carabiner-dev/vexflow/pkg/api/v1"
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

// PublishAttestation pushes an attested VEX document to the GitHub
// attestations store for the configured repository.
func (p *Publisher) PublishAttestation(att attestation.Statement) (*api.StatementNotice, error) {
	sg := signer.NewSigner()
	data, err := json.Marshal(att)
	if err != nil {
		return nil, fmt.Errorf("marshaling attestation: %w", err)
	}
	signed, err := sg.SignStatementBundle(data)
	if err != nil {
		return nil, fmt.Errorf("signing statement: %w", err)
	}

	// Wrap the signed bundle as an attestation.Envelope so the
	// collector's github driver can upload it. Merge instead of
	// dereferencing to avoid copying the proto message's lock.
	env := &bundleenv.Envelope{}
	proto.Merge(&env.Bundle, signed.Bundle)

	// Build the GitHub attestations driver and store the bundle.
	driver, err := cdgh.New(
		cdgh.WithOwner(p.Options.Org),
		cdgh.WithRepo(p.Options.Repo),
	)
	if err != nil {
		return nil, fmt.Errorf("building github attestations driver: %w", err)
	}
	if err := driver.Store(context.Background(), attestation.StoreOptions{}, []attestation.Envelope{env}); err != nil {
		return nil, fmt.Errorf("uploading attestation: %w", err)
	}

	return &api.StatementNotice{
		Published: time.Now(),
		Location:  fmt.Sprintf("github.com/%s/%s", p.Options.Org, p.Options.Repo),
	}, nil
}

func (p *Publisher) ReadBranchVEX(branch *api.Branch) ([]attestation.Envelope, error) {
	if p.Options.Org == "" || p.Options.Repo == "" {
		return nil, errors.New("no repository data set in options")
	}
	// Build the github attestations driver and the collector agent.
	driver, err := cdgh.New(
		cdgh.WithOwner(p.Options.Org),
		cdgh.WithRepo(p.Options.Repo),
	)
	if err != nil {
		return nil, fmt.Errorf("building github attestations driver: %w", err)
	}
	agent, err := collector.New(collector.WithRepository(driver))
	if err != nil {
		return nil, fmt.Errorf("building collector agent: %w", err)
	}
	attestations, err := agent.FetchAttestationsBySubject(context.Background(), []attestation.Subject{
		branch.ToResourceDescriptor(),
	})
	if err != nil {
		return nil, fmt.Errorf("fetching branch attestations: %w", err)
	}

	// Filter attestations to return only the VEX docs.
	query := attestation.NewQuery().WithFilter(&filters.PredicateTypeMatcher{
		PredicateTypes: map[attestation.PredicateType]struct{}{
			attestation.PredicateType("https://openvex.dev/ns"):        {},
			attestation.PredicateType("https://openvex.dev/ns@v0.2.0"): {},
		},
	})

	return query.Run(attestations, attestation.WithMode(attestation.QueryModeOr)), nil
}
