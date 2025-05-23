// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package flow

import (
	"fmt"

	api "github.com/carabiner-dev/vexflow/pkg/api/v1"
)

type initFunc func(*Manager) error

func WithBackend(tb api.TriageBackend) initFunc {
	return func(m *Manager) error {
		if tb == nil {
			return fmt.Errorf("triage backend not defined")
		}
		m.triageBackend = tb
		return nil
	}
}

func WithScanner(s api.Scanner) initFunc {
	return func(m *Manager) error {
		if s == nil {
			return fmt.Errorf("triage backend not defined")
		}
		m.scanner = s
		return nil
	}
}

func WithPublisher(p api.VexPublisher) initFunc {
	return func(m *Manager) error {
		if p == nil {
			return fmt.Errorf("vex publisher not defined")
		}
		m.publisher = p
		return nil
	}
}

func WithSSH(use bool) initFunc {
	return func(m *Manager) error {
		m.Options.UseSSH = use
		return nil
	}
}
