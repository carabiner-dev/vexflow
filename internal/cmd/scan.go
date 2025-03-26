// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"

	gointoto "github.com/in-toto/attestation/go/v1"

	api "github.com/carabiner-dev/vexflow/pkg/api/v1"
	"github.com/carabiner-dev/vexflow/pkg/flow"
	"github.com/carabiner-dev/vexflow/pkg/scanner/osv"
)

type scanPathOptions struct {
	Path   string
	Format string
	Attest bool
}

var scanFormats = []string{"table", "osv"}

// Validates the options in context with arguments
func (so *scanPathOptions) Validate() error {
	errs := []error{}
	if so.Path == "" {
		errs = append(errs, errors.New("path to code directory not set"))
	}

	if !slices.Contains(scanFormats, so.Format) {
		errs = append(errs, fmt.Errorf("invalid format, supported values: %+v", scanFormats))
	}

	return errors.Join(errs...)
}

// AddFlags adds the subcommands flags
func (so *scanPathOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(
		&so.Path, "path", ".", "path top the codebase to scan",
	)
	cmd.PersistentFlags().StringVarP(
		&so.Format, "format", "f", "table", fmt.Sprintf("output format (%+v)", scanFormats),
	)

	cmd.PersistentFlags().BoolVarP(
		&so.Attest, "attest", "a", false, "output as an attestation (implies --format=osv)",
	)
}

func addScan(parentCmd *cobra.Command) {
	scanCommand := &cobra.Command{
		Short:        "list the vulnerabilities the configured scanner sees",
		Use:          "scan [path|repo] scanning/target",
		SilenceUsage: false,
		Long: `
vexflow scan [path|repo]: List vulnerabilities found by the configured scanner.

The can command invokes the configured scanner and returns the vulnerabilities
it sees in a codebase. scan has two subcommands:

vexflow scan path /path/to/code

Calls the scanner in a local codebase, returning the vulnerability list.

vexflow scan repo github.com/organization/repository

The repo subcommand works like path but clones the repository from the
remote URL and runs the scanner in the local copy.

By default vexflow scan outputs its findings to a table on STDOUT. The results
can also be output in the OSV format optionally wrapped in an attestation.

`,
	}
	addScanPath(scanCommand)
	parentCmd.AddCommand(scanCommand)
}

func addScanPath(parentCmd *cobra.Command) {
	opts := &scanPathOptions{}
	triageCommand := &cobra.Command{
		Short:             "list the vulnerabilities in a local codebase as seen by the scanner",
		Use:               "path",
		Example:           fmt.Sprintf(`%s scan --repo org/repo --branch=main `, appname),
		SilenceUsage:      false,
		SilenceErrors:     true,
		PersistentPreRunE: initLogging,
		Long: `
	vexflow scan path: Scan a local directory
	The vexflow scan path subcommand runs the configured scanner to extract
	vulnerabilities on a local codebase:
	vexflow scan path /my/directory
	By default, the subcommand outputs the vulnerabilities as an on screen
	table but the scan family of subcommands can also output the data as an
	OSV schema formatted JSON file:
	vexflow scan path --format=osv /my/directory
	Using the --attest flag will wrap the OSV JSON data in an attestation. In order
	to generate the attestation, the target directory needs to be a git repository 
	and vexflow needs to be able to read the git data to determine the branch and 
	remote.
	vexflow scan path --format=osv --attest /my/directory
	`,
		PreRunE: func(_ *cobra.Command, args []string) error {
			if len(args) > 0 {
				if opts.Path != "." && opts.Path != "" && opts.Path != args[0] {
					return errors.New("code directory specified twice")
				}
				opts.Path = args[0]
			}
			if opts.Attest {
				opts.Format = "osv"
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			// Validate the options
			if err := opts.Validate(); err != nil {
				return err
			}
			mgr, err := flow.New(
				flow.WithScanner(osv.New()),
			)
			if err != nil {
				return err
			}
			branch := &api.Branch{
				ClonePath: opts.Path,
			}
			vulns, err := mgr.ScanBranchCode(branch)
			if err != nil {
				return err
			}

			var out io.Writer = os.Stdout

			if opts.Format == "osv" {
				if opts.Attest {
					attestation, err := mgr.VulnsToAttestation(&gointoto.ResourceDescriptor{
						Name:             "",
						Uri:              "",
						Digest:           map[string]string{},
						Content:          []byte{},
						DownloadLocation: "",
						MediaType:        "",
						Annotations:      &structpb.Struct{},
					}, vulns)
					if err != nil {
						return err
					}

					enc := json.NewEncoder(out)
					enc.SetIndent("", "  ")
					if err := enc.Encode(attestation); err != nil {
						return fmt.Errorf("marshaling attestation: %w", err)
					}
					return nil
				}

				// If not an attestation, just output the OSV data:
				osvdata, err := mgr.VulnsToOSV(vulns)
				if err != nil {
					return err
				}

				data, err := protojson.MarshalOptions{
					Multiline: true,
					Indent:    "  ",
				}.Marshal(osvdata)
				if err != nil {
					return fmt.Errorf("marshaling OSV data: %w", err)
				}

				// Output the marshalled data
				if _, err := out.Write(data); err != nil {
					return err
				}
				return nil
			}
			t := table.New().
				Border(lipgloss.NormalBorder()).
				BorderStyle(lipgloss.NewStyle().Foreground(purple)).
				StyleFunc(func(row, col int) lipgloss.Style {
					switch {
					case row == table.HeaderRow:
						return headerStyle
					case row%2 == 0:
						return evenRowStyle
					default:
						return oddRowStyle
					}
				}).
				Headers("VULNERABILITY", "ALIASES", "COMPONENT")

			for _, vuln := range vulns {
				t.Row(
					vuln.ID,
					strings.Join(vuln.Aliases, "\n"),
					vuln.ComponentPurl(),
				)
			}
			fmt.Println(t)
			return nil
		},
	}
	opts.AddFlags(triageCommand)
	parentCmd.AddCommand(triageCommand)
}
