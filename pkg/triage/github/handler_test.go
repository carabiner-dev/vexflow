// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package github

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestListIssues(t *testing.T) {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		t.Skip("no token  set, skipping test")
	}
	handler, err := New()
	require.NoError(t, err)

	handler.options.Org = "protobom"
	handler.options.Repo = "protobom"

	issues, err := handler.listIssues(t.Context())
	require.NoError(t, err)
	require.NotNil(t, issues)
	require.Len(t, issues, 20)
}
