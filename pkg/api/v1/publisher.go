// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1

import "github.com/openvex/go-vex/pkg/vex"

type VexPublisher interface {
	PublishDocument(*vex.VEX) (*StatementNotice, error)
}
