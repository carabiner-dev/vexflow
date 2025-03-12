// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package osvcmdline

import (
	"os"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProcessOSVreport(t *testing.T) {
	data, err := os.ReadFile("testdata/scan.json")
	require.NoError(t, err)

	vulns, err := processOSVreport(string(data))
	require.NoError(t, err)
	require.NotNil(t, vulns)
	require.Len(t, vulns, 4)

	ids := []string{}
	packages := []string{}
	for _, v := range vulns {
		ids = append(ids, v.ID)
		packages = append(packages, v.Component.Purl)
	}

	slices.Sort(ids)
	slices.Sort(packages)

	require.Equal(t, []string{"CVE-2024-45338", "CVE-2024-45338", "CVE-2025-22868", "CVE-2025-22869"}, ids)
	require.Equal(t, []string{"pkg:golang/golang.org/x/crypto@0.31.0", "pkg:golang/golang.org/x/net@0.32.0", "pkg:golang/golang.org/x/net@0.32.0", "pkg:golang/golang.org/x/oauth2@0.24.0"}, packages)
}
