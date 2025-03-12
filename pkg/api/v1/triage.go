// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1

type TriageStatus string

const (
	StatusClosed              TriageStatus = "CLOSED"
	StatusWaitingForAsessment TriageStatus = "WAITING_USER"
	StatusWaitingForStatement TriageStatus = "WAITING_STATEMENT"
	StatusWaitingForClose     TriageStatus = "FIN_WAIT"
)

type Triage struct {
	BackendID     string          `json:"backend_id"`
	Vulnerability *Vulnerability  `json:"vulnerability"`
	Branch        *Branch         `json:"branch"`
	Status        TriageStatus    `json:"status"`
	SlashCommands []*SlashCommand `json:"-"`
}

func (t *Triage) LastCommand() *SlashCommand {
	if len(t.SlashCommands) == 0 {
		return nil
	}
	return t.SlashCommands[len(t.SlashCommands)-1]
}

type TriageBackend interface {
	ListBranchTriages(*Branch) ([]*Triage, error)
	CreateTriage(*Branch, *Vulnerability) (*Triage, error)
	ReadTriageStatus(*Triage) error
}
