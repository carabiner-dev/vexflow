package v1

import (
	"strings"
	"time"

	"github.com/openvex/go-vex/pkg/vex"
)

const (
	CommandAffected           = "/affected"
	CommandNotAffected        = "/not_affected"
	CommandFixed              = "/fixed"
	CommandUnderInvestigation = "/under_investigation"

	JustificationComponentNotPresent                         = "component_not_present"
	JustificationVulnerableCodeNotPresent                    = "vulnerable_code_not_present"
	JustificationVulnerableCodeNotInExecutePath              = "vulnerable_code_not_in_execute_path"
	JustificationVulnerableCodeCannotBeControlledByAdversary = "vulnerable_code_cannot_be_controlled_by_adversary"
	JustificationInlineMitigationsAlreadyExist               = "inline_mitigations_already_exist"
)

type SlashCommand struct {
	Command      string
	Date         time.Time
	Blurb        string
	AuthorHandle string
	Raw          string
	Notice       *StatementNotice
}

func (sc *SlashCommand) Subcommand() string {
	_, s, _ := strings.Cut(sc.Command, ":")
	return s
}

func (sc *SlashCommand) VexJustification() vex.Justification {
	switch sc.Subcommand() {
	case JustificationComponentNotPresent:
		return vex.ComponentNotPresent
	case JustificationVulnerableCodeNotPresent:
		return vex.VulnerableCodeNotPresent
	case JustificationVulnerableCodeNotInExecutePath:
		return vex.VulnerableCodeNotInExecutePath
	case JustificationVulnerableCodeCannotBeControlledByAdversary:
		return vex.VulnerableCodeCannotBeControlledByAdversary
	case JustificationInlineMitigationsAlreadyExist:
		return vex.InlineMitigationsAlreadyExist
	default:
		return ""
	}
}

func (sc *SlashCommand) VexStatus() vex.Status {
	switch sc.Command {
	case CommandAffected:
		return vex.StatusAffected
	case CommandFixed:
		return vex.StatusFixed
	case CommandUnderInvestigation:
		return vex.StatusUnderInvestigation
	default:
		if strings.HasPrefix(sc.Command, CommandNotAffected) {
			return vex.StatusNotAffected
		}
		return ""
	}
}

type StatementNotice struct {
	Published   time.Time `json:"published"`
	Status      string    `json:"status"`
	StatementID string    `json:"statement_id"`
	Location    string    `json:"location"`
}
