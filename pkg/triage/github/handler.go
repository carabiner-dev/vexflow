// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package github

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"

	gogithub "github.com/google/go-github/v60/github"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"

	api "github.com/carabiner-dev/vexflow/pkg/api/v1"
)

var ErrRepositoryNotFound = errors.New("the specified triage repository does not exist")

func ParseSlug(slug string) (org, repo string, err error) {
	parts := strings.Split(slug, "/")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid repo slug %q", slug)
	}
	return parts[0], parts[1], nil
}

func New(funcs ...fnOption) (*TriageHandler, error) {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("GITHUB_TOKEN not set")
	}

	httpClient := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	))

	client := gogithub.NewClient(httpClient)
	th := &TriageHandler{
		options: Options{},
		client:  client,
	}

	for _, fn := range funcs {
		if err := fn(th); err != nil {
			return nil, err
		}
	}

	return th, nil
}

type TriageHandler struct {
	options Options
	Owners  *Owners
	client  *gogithub.Client
}

// ReadStatusList
func (th *TriageHandler) ReadStatusList([]*api.Vulnerability) {
}

// EnsureOwnersData reads the OWNERS data if its not set.
func (th *TriageHandler) EnsureOwnersData() error {
	if th.Owners == nil {
		// Parse the owners file
		if err := th.ReadOwners(); err != nil {
			return fmt.Errorf("parsing owners file: %w", err)
		}
	}
	return nil
}

// ListTriages returns a list of all triages in a repo for a branch
func (th *TriageHandler) ListBranchTriages(branch *api.Branch) ([]*api.Triage, error) {
	if branch.Identifier() == "" {
		return nil, fmt.Errorf("branch identifier is invalid")
	}

	issues, err := th.listIssues(context.Background())
	if err != nil {
		return nil, fmt.Errorf(
			"fetching issues from %s/%s: %w", th.options.Org, th.options.Repo, err,
		)
	}

	ret := []*api.Triage{}
	logrus.Debugf("backend returned %d issues", len(issues))

	for _, i := range issues {
		embedded, err := extractEmbeddedMessage(i)
		// TODO(puerco): Ignore malformed
		if err != nil {
			return nil, fmt.Errorf("parsing issue %d: %w", i.GetNumber(), err)
		}

		if embedded == nil {
			continue
		}

		if i.GetState() == "closed" {
			embedded.Status = api.StatusClosed
		}

		// Assign the issue number to the triage object
		embedded.BackendID = fmt.Sprintf("%d", i.GetNumber())

		if embedded.Status != api.StatusClosed {
			if err := th.ReadTriageStatus(&embedded.Triage); err != nil {
				return nil, err
			}
		}

		if embedded.BranchID == branch.Identifier() {
			ret = append(ret, &embedded.Triage)
		}
	}
	return ret, nil
}

// extractEmbeddedMessage reads the data embedded by vexflow into the issue body
func extractEmbeddedMessage(issue *gogithub.Issue) (*EmbeddedMessage, error) {
	body := issue.GetBody()
	if !strings.Contains(body, bodySeparator) {
		return nil, nil
	}

	parts := strings.Split(body, bodySeparator)
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed issue body (issue #%d)", issue.GetNumber())
	}

	embedded := &EmbeddedMessage{}
	if err := json.Unmarshal([]byte(parts[1]), embedded); err != nil {
		return nil, fmt.Errorf("parsing triage data from issue: %w", err)
	}

	return embedded, nil
}

// listIssues returns all the open issues
func (th *TriageHandler) listIssues(ctx context.Context) ([]*gogithub.Issue, error) {
	issues := []*gogithub.Issue{}
	page := 0
	for {
		opts := &gogithub.IssueListByRepoOptions{
			State: "all", // o open o closed
			// Creator:   "", ?? tal vez?
			// Labels: []string{},
			// Sort:      "", // created, updated, and comments
			// Direction: "", // asc, desc.
			// Since: time.Time{},
			ListOptions: gogithub.ListOptions{
				Page:    page,
				PerPage: 100,
			},
		}
		moreIssues, response, err := th.client.Issues.ListByRepo(ctx, th.options.Org, th.options.Repo, opts)
		if err != nil {
			if strings.Contains(err.Error(), "404 Not Found") {
				return nil, ErrRepositoryNotFound
			}
			return nil, fmt.Errorf("fetching issues from repo: %w", err)
		}

		issues = append(issues, moreIssues...)

		if page = response.NextPage; page == 0 {
			break
		}
	}
	return issues, nil
}

// CreateTriage starts a new triage for a vulnerability
func (th *TriageHandler) CreateTriage(branch *api.Branch, vuln *api.Vulnerability) (*api.Triage, error) {
	if vuln.ID == "" {
		return nil, fmt.Errorf("unable to start triage process, vulnerability has no ID")
	}

	// Generate the Issue body
	body, err := th.generateIssueBody(branch, vuln)
	if err != nil {
		return nil, fmt.Errorf("generating traige message: %w", err)
	}

	// Call the GitHub API to create the issue
	title := fmt.Sprintf("%s: VEX Exploitability Triage", vuln.ID)
	issue, _, err := th.client.Issues.Create(context.Background(), th.options.Org, th.options.Repo, &gogithub.IssueRequest{
		Title: &title,
		Body:  &body,
		// Labels: &[]string{},
		//Assignee:    new(string),
		//State:       new(string),
		//StateReason: new(string),
		//Milestone:   new(int),
		///Assignees:   &[]string{},
	})
	if err != nil {
		return nil, fmt.Errorf("posting new issue: %w", err)
	}

	return &api.Triage{
		BackendID:     fmt.Sprintf("%d", issue.GetNumber()),
		Vulnerability: vuln,
		Branch:        branch,
		Status:        api.StatusWaitingForAsessment,
	}, nil
}

// ReadTriageStatus enriches a triage with data from the comment history
func (th *TriageHandler) ReadTriageStatus(t *api.Triage) error {
	if err := th.EnsureOwnersData(); err != nil {
		return err
	}

	nr, err := getIssueNumber(t)
	if err != nil {
		return err
	}

	// Read all the issue comments
	comments, _, err := th.client.Issues.ListComments(
		context.Background(), th.options.Org, th.options.Repo, nr,
		&gogithub.IssueListCommentsOptions{
			Sort:        gogithub.String("created"),
			Direction:   gogithub.String("asc"),
			ListOptions: gogithub.ListOptions{PerPage: 100},
		},
	)
	if err != nil {
		return fmt.Errorf("fetching issue data: %w", err)
	}

	logrus.Debugf("processing %d comments from issue %d", len(comments), nr)

	currentStatus := api.StatusWaitingForAsessment
	var lastSlashcommand *api.SlashCommand
	for i, c := range comments {
		// 1. Check if the comment is a slash command:
		slashCommand, err := parseSlashCommand(c)
		if err != nil {
			return fmt.Errorf("parsing comment for slash command")
		}

		if slashCommand != nil {
			// If the comment with the slash command is not from someone in
			// the OWNERS file, then we skip it. If this is the last comment
			// in the issue, at some point we should reply saying it will not
			// have any effect in the triage
			if !slices.Contains(th.Owners.Approvers, *c.User.Login+"a") {
				logrus.Debugf("Ignoring comment #%d from %s as they are not in the OWNERS file", i, *c.User.Login)
				// This only works with fine-grained tokens with issues;write
				// permissions. We try everytime even when it fails
				if _, _, err := th.client.Reactions.CreateCommentReaction(
					context.Background(), th.options.Org, th.options.Repo, *c.ID, "confused",
				); err != nil {
					logrus.Debugf("Error creating reaction: %s", err)
				}
				// If this is the last comment, reply saying the comment
				// will be ignored.
				if i == len(comments)-1 {
					if _, _, err := th.client.Issues.CreateComment(
						context.Background(), th.options.Org, th.options.Repo, nr,
						&gogithub.IssueComment{
							Body: gogithub.String(
								fmt.Sprintf(
									"Unfortunately, @%s is not in the OWNERS file for this branch. Vexflow cannot react to the slash command.",
									*c.User.Login,
								),
							),
						},
					); err != nil {
						return fmt.Errorf("posting publishing notice comment: %w", err)
					}
				}
				continue
			}

			if err := validateSlashCommand(slashCommand); err != nil {
				return err
			}

			currentStatus = api.StatusWaitingForStatement
			lastSlashcommand = slashCommand
			t.SlashCommands = append(t.SlashCommands, slashCommand)
			continue
		}

		// If not, check if its a publish notice from vexflow
		notice, err := parsePublishNotice(c)
		if err != nil {
			// Probably don't fail on this one
			return fmt.Errorf("parsing notice: %w", err)
		}
		if notice != nil {
			currentStatus = api.StatusWaitingForClose
			if lastSlashcommand != nil && lastSlashcommand.Notice == nil {
				lastSlashcommand.Notice = notice
			}
		}
	}

	if t.Status != api.StatusClosed {
		t.Status = currentStatus
	}
	return nil
}

// Parses the slash command data from an issue comment
func parseSlashCommand(c *gogithub.IssueComment) (*api.SlashCommand, error) { //nolint:unparam //  TODO Check valid command
	rawText := c.GetBody()
	if rawText == "" {
		return nil, nil
	}

	rawText = strings.TrimSpace(rawText)
	scanner := bufio.NewScanner(strings.NewReader(rawText))
	i := 0
	var firstLine, blurb string
	for scanner.Scan() {
		i++
		if i == 1 {
			firstLine = scanner.Text()
			continue
		}
		blurb += scanner.Text()
	}

	parts := strings.Split(strings.TrimSpace(firstLine), " ")
	if !strings.HasPrefix(parts[0], "/") {
		return nil, nil
	}

	return &api.SlashCommand{
		Command:      parts[0],
		Date:         c.CreatedAt.Time,
		Blurb:        strings.TrimSpace(blurb),
		AuthorHandle: c.GetUser().GetLogin(),
		Raw:          rawText,
	}, nil
}

// validateSlashCommand checks a slash command to ensure it is valid
func validateSlashCommand(cmd *api.SlashCommand) error {
	if cmd == nil {
		return fmt.Errorf("slash command is nil")
	}
	command, subcommand, _ := strings.Cut(cmd.Command, ":")
	switch command {
	case api.CommandAffected, api.CommandUnderInvestigation, api.CommandFixed:
		return nil
	case api.CommandNotAffected:
		if subcommand == "" {
			return errors.New("a not_affected status needs a status justfication label")
		}
		switch subcommand {
		case api.JustificationComponentNotPresent,
			api.JustificationVulnerableCodeNotPresent,
			api.JustificationVulnerableCodeNotInExecutePath,
			api.JustificationVulnerableCodeCannotBeControlledByAdversary,
			api.JustificationInlineMitigationsAlreadyExist:
			return nil
		default:
			return fmt.Errorf("invalid not_affected status justification label")
		}
	default:
		return fmt.Errorf("invalid slash command %q", command)
	}
}

// parsePublishNotice parses a VEX statement publishing notice from an issue comment
func parsePublishNotice(c *gogithub.IssueComment) (*api.StatementNotice, error) {
	rawBody := c.GetBody()
	if !strings.Contains(rawBody, bodySeparatorNotice) {
		return nil, nil
	}

	parts := strings.Split(rawBody, bodySeparatorNotice)
	if len(parts) < 2 {
		return nil, fmt.Errorf("parsing notice from comment")
	}

	notice := &api.StatementNotice{}
	if err := json.Unmarshal([]byte(parts[1]), notice); err != nil {
		return nil, fmt.Errorf("parsing statement notice json: %w", err)
	}

	return notice, nil
}

func getIssueNumber(t *api.Triage) (int, error) {
	var nr int
	if t.BackendID != "" {
		i, err := strconv.Atoi(t.BackendID)
		if err != nil {
			return 0, fmt.Errorf("parsing issue number")
		}
		nr = i
	}
	if nr == 0 {
		return 0, fmt.Errorf("issue number not found")
	}
	return nr, nil
}

// AppendPublishNotice appends publishing notices to the issue conversation
func (th *TriageHandler) AppendPublishNotice(t *api.Triage, notice *api.StatementNotice) error {
	nr, err := getIssueNumber(t)
	if err != nil {
		return err
	}

	cmd := t.LastCommand()
	if cmd == nil {
		return fmt.Errorf("unable to find last slash command in triage")
	}

	if cmd.Notice != nil {
		return fmt.Errorf("last slash command already has a publish notice")
	}

	// Generate the comment text
	commentText, err := generatePublishNoticeComment(t, notice)
	if err != nil {
		return fmt.Errorf("generating issue comment: %w", err)
	}

	// Publish comment to issue
	if _, _, err := th.client.Issues.CreateComment(
		context.Background(), th.options.Org, th.options.Repo, nr,
		&gogithub.IssueComment{
			Body: gogithub.String(commentText),
		},
	); err != nil {
		return fmt.Errorf("posting publishing notice comment: %w", err)
	}

	// Append notice to triage
	cmd.Notice = notice

	// Done
	return nil
}

// CloseTriage translates to closing the issue on github.
func (th *TriageHandler) CloseTriage(t *api.Triage) error {
	nr, err := getIssueNumber(t)
	if err != nil {
		return err
	}
	if _, _, err := th.client.Issues.Edit(context.Background(), th.options.Org, th.options.Repo, nr, &gogithub.IssueRequest{
		State:       gogithub.String("closed"),
		StateReason: gogithub.String("completed"),
	}); err != nil {
		return fmt.Errorf("closing issue #%d: %w", nr, err)
	}
	t.Status = api.StatusClosed
	return nil
}

// CloseTriageWithMessage closes an open triage leaving a comment before doing so.
func (th *TriageHandler) CloseTriageWithMessage(t *api.Triage, msg string) error {
	nr, err := getIssueNumber(t)
	if err != nil {
		return err
	}
	// Publish comment to issue
	if _, _, err := th.client.Issues.CreateComment(
		context.Background(), th.options.Org, th.options.Repo, nr,
		&gogithub.IssueComment{
			Body: gogithub.String(msg),
		},
	); err != nil {
		return fmt.Errorf("posting publishing notice comment: %w", err)
	}

	return th.CloseTriage(t)
}
