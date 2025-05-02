// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/carabiner-dev/hasher"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/spf13/cobra"
	"sigs.k8s.io/release-utils/util"

	api "github.com/carabiner-dev/vexflow/pkg/api/v1"
	"github.com/carabiner-dev/vexflow/pkg/flow"
	ghpublish "github.com/carabiner-dev/vexflow/pkg/publish/github"
	"github.com/carabiner-dev/vexflow/pkg/scanner/osv"
	"github.com/carabiner-dev/vexflow/pkg/triage/github"
)

var (
	hashRegexStr = `^(\bsha1\b|\bsha256\b|\bsha512\b|\bsha3\b|\bgitCommit\b):([a-f0-9]+)$`
	hashRegex    *regexp.Regexp
)

type assembleOptions struct {
	repoOptions
	outFileOptions
	productFile []string
}

// Validates the options in context with arguments
func (ao *assembleOptions) Validate() error {
	errs := []error{}
	if err := ao.repoOptions.Validate(); err != nil {
		errs = append(errs, err)
	}
	if err := ao.outFileOptions.Validate(); err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

// AddFlags adds the subcommands flags
func (ao *assembleOptions) AddFlags(cmd *cobra.Command) {
	ao.repoOptions.AddFlags(cmd)
	ao.outFileOptions.AddFlags(cmd)
	cmd.PersistentFlags().StringSliceVarP(
		&ao.productFile, "product", "p", nil, "files or hashes to add as additional products",
	)
}

func addAssemble(parentCmd *cobra.Command) {
	opts := &assembleOptions{}
	assembleCommand := &cobra.Command{
		Short: "assemble a build document from branch data",
		Long: `
vexflow assemble: build an OpenVEX document for a branch

The assemble document gathers all the applicable VEX data for a branch and 
builds an OpenVEX document with all statements that apply to it. This
subcommand is useful to compute the VEX data capturing the exploitability
data of a branch just before cutting a release.

To compute  the needed data, vexflow will:

1. Clone the repository and run the configured scanner

2. Gather all available VEX data

3. Filter the statements applicable to the vulnerabilities still
   present in the codebase.

Once the remaining data has been gathered, a new OpenVEX document will be
generated to STDOUT (or to the path specified by --out).

		`,
		Use:               "assemble",
		Example:           fmt.Sprintf(`%s assemble --repo org/repo --branch=main `, appname),
		SilenceUsage:      false,
		SilenceErrors:     true,
		PersistentPreRunE: initLogging,
		PreRunE: func(_ *cobra.Command, args []string) error {
			if len(args) > 0 {
				if opts.RepoSlug != "" && opts.RepoSlug != args[0] {
					return fmt.Errorf("repository specified twice")
				}
				opts.RepoSlug = args[0]
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			// Validate the options
			if err := opts.Validate(); err != nil {
				return err
			}

			backendOrg, backendRepo, err := opts.GetBackendRepo()
			if err != nil {
				return err
			}

			// Init the github backend to the triage repository
			backend, err := github.New(
				github.WithTriageOrg(backendOrg),
				github.WithTriageRepo(backendRepo),
			)
			if err != nil {
				return fmt.Errorf("creating github backend: %w", err)
			}

			publisher, err := ghpublish.New(
				ghpublish.WithOrg(backendOrg),
				ghpublish.WithRepo(backendRepo),
			)
			if err != nil {
				return err
			}

			mgr, err := flow.New(
				flow.WithBackend(backend),
				flow.WithScanner(osv.New()),
				flow.WithPublisher(publisher),
			)
			if err != nil {
				return err
			}

			org, repo, err := github.ParseSlug(opts.RepoSlug)
			if err != nil {
				return err
			}
			branch := &api.Branch{
				Repository: fmt.Sprintf("github.com/%s/%s", org, repo),
				Name:       opts.BranchName,
			}

			h := hasher.New()
			var files = []string{}
			var descriptors = []*intoto.ResourceDescriptor{}
			for _, pf := range opts.productFile {
				if util.Exists(pf) {
					files = append(files, pf)
				} else {
					rd := stringToDescriptor(pf)
					if rd != nil {
						descriptors = append(descriptors, rd)
					}
				}
			}
			hashes, err := h.HashFiles(files)
			if err != nil {
				return err
			}
			descriptors = append(descriptors, hashes.ToResourceDescriptors()...)

			doc, err := mgr.AssembleBranchDocument(branch, descriptors...)
			if err != nil {
				return fmt.Errorf("assembling doc: %w", err)
			}

			var out io.Writer = os.Stdout
			return doc.ToJSON(out)
		},
	}
	opts.AddFlags(assembleCommand)
	parentCmd.AddCommand(assembleCommand)
}

func stringToDescriptor(subjString string) *intoto.ResourceDescriptor {
	if hashRegex == nil {
		hashRegex = regexp.MustCompile(hashRegexStr)
	}

	// If the string matches algo:hexValue then we never try to look
	// for a file. Never.
	pts := hashRegex.FindStringSubmatch(subjString)
	if pts == nil {
		return nil
	}

	algo := strings.ToLower(pts[1])
	if _, ok := intoto.HashAlgorithms[algo]; !ok {
		return nil
	}

	return &intoto.ResourceDescriptor{
		Digest: map[string]string{algo: pts[2]},
	}
}
