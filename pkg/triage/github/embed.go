// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package github

import (
	"encoding/json"
	"errors"
	"fmt"

	api "github.com/carabiner-dev/vexflow/pkg/api/v1"
)

const (
	bodySeparator       = "### VEXFLOW==DATA ###"
	bodySeparatorNotice = "### VEXFLOW==NOTICE ###"
)

type EmbeddedMessage struct {
	BranchID string `json:"branch_id"`
	api.Triage
}

func (th *TriageHandler) generateIssueBody(branch *api.Branch, vuln *api.Vulnerability) (string, error) {
	if branch.Identifier() == "" {
		return "", errors.New("branch identifier is empty")
	}
	message := &EmbeddedMessage{
		BranchID: branch.Identifier(),
		Triage: api.Triage{
			Vulnerability: vuln,
			Status:        api.StatusWaitingForAsessment,
			Branch:        branch,
		},
	}

	data, err := json.Marshal(message)
	if err != nil {
		return "", fmt.Errorf("marshaling embedded message: %s", err)
	}

	embed := "<!--\n" + bodySeparator + "\n" + string(data) + "\n" + bodySeparator + "\n-->"

	summaryRow := ""
	if vuln.Summary != "" {
		summaryRow = fmt.Sprintf("\n| | %s ", vuln.Summary)
		if vuln.Details != "" {
			summaryRow += fmt.Sprintf("|\n%s ", vuln.Details)
		}
		summaryRow += "|\n"
	}

	return fmt.Sprintf(`
# Exploitability triage for %s

This issue tracks the exploitability triage process for `+"`"+`%s`+"`"+`.
Based on the outcome of this issue, VEX (vulnerability exploitability exchange)
data will be published to describe the impact on the project.

## Triage Instructions:

If you are an authorized maintainer, comment on this issue to signal the vexflow
client how to move forward.

First, determine if the vulnerability affects the project branch:

| | |
| --- | --- | 
| __Vulnerability__ | %s |%s
| __Repository__ | %s | 
| __Branch__ | %s |
| __Component__ | %s |

To register your assessment, determine if it affects the project branch and add
a slash command in a comment to generate the appropriate VEX statement:

### 🏷️ Not Affected

If the vulnerability does not impact the software project branch, issue a not_affected
statement. Follow the slash command with one of the VEX justification labels. Any 
extra text will be treated as the VEX impact statement.

`+"`"+`/not_affected:component_not_present`+"`"+`
`+"`"+`/not_affected:vulnerable_code_not_present`+"`"+`
`+"`"+`/not_affected:vulnerable_code_not_in_execute_path`+"`"+`
`+"`"+`/not_affected:vulnerable_code_cannot_be_controlled_by_adversary`+"`"+`
`+"`"+`/not_affected:inline_mitigations_already_exist`+"`"+`

__Example Comment:__

> `+"`"+`/not_affected:inline_mitigations_already_exist`+"`"+`
>
> The released artifacts have been patched with a custom fix, the vulnerability
> Is no longer present.

### 🏷️ Affected

To assess the project _is_ affected by a vulnerability, issue an  
`+"`"+`affected`+"`"+` statement. Any text after the slash command will be
treated as the action_statement to be published along the status:

`+"`"+`/affected`+"`"+`

__Example Comment:__

> `+"`"+`/affected`+"`"+`
>
> The product is affected by CVE-1234-5678, it is recommended to firewall port
> 9000 while a patch is issued a new version is released.


### 🏷️ Fixed

For completeness' sake, you can issue a `+"`"+`fixed`+"`"+` statement. For normal
development flows, this is not required as vulnerabilities will no longer show
up in the code when dependencies are updated.

`+"`"+`/fixed`+"`"+`

__Example Comment:__

> `+"`"+`/fixed`+"`"+`

### Handling This Issue

Closing this issue will stop the triage process. Once closed, vexflow will not
start a new triage process for the same vulnerability for the same
branch+component.

> [!NOTE]
> This issue's body contains hidden machine readable data to keep track of the
> triage process. Don't modify this message.

%s

`,
		vuln.ID, vuln.ID,
		// Table
		vuln.ID, summaryRow, branch.Repository, branch.Name, vuln.Component.Purl,
		embed,
	), nil
}

func generatePublishNoticeComment(t *api.Triage, notice *api.StatementNotice) (string, error) {
	// Marshal the notice to json
	data, err := json.Marshal(notice)
	if err != nil {
		return "", fmt.Errorf("marshaling publish notice: %w", err)
	}

	dataBlock := "<!--\n" + bodySeparatorNotice + "\n" + string(data) + "\n" + bodySeparatorNotice + "\n-->\n"

	author := ""
	if t.LastCommand() != nil {
		author = " @" + t.LastCommand().AuthorHandle
	}

	comment := fmt.Sprintf("Thanks for the assessment%s!\n\n", author)
	comment += fmt.Sprintf("A VEX statement has been published capturing your review of the impact of %s ", t.Vulnerability.ID)
	comment += "on the project. This issue will now be closed and no further action is needed.\n\n"
	comment += "If the exploitability status changes, feel free to open this issue again and "
	comment += "issue a new slash command to update the VEX status.\n"
	comment += dataBlock

	return comment, nil
}
