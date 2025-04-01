// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/spf13/cobra"
)

type outFileOptions struct {
	OutPath string
}

// Validates the options in context with arguments
func (ofo *outFileOptions) Validate() error {
	return nil
}

// AddFlags adds the subcommands flags
func (ofo *outFileOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVarP(
		&ofo.OutPath, "out", "o", "", "path to write output (defaults to STDOUT)",
	)
}
