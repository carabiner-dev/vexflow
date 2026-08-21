// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"github.com/carabiner-dev/attestation"
	"github.com/openvex/go-vex/pkg/vex"
)

type VexPublisher interface {
	PublishDocument(*vex.VEX) (*StatementNotice, error)
	PublishAttestation(att attestation.Statement) (*StatementNotice, error)
	ReadBranchVEX(*Branch) ([]attestation.Envelope, error)
}
