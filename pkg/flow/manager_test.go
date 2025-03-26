package flow

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetLocalRepoRemoteURL(t *testing.T) {
	t.Parallel()
	url, err := getLocalRepoRemoteURL("../../")
	require.NoError(t, err, url)
	require.NotEmpty(t, url)

	_, err = getLocalRepoRemoteURL("/cheetos")
	require.Error(t, err)
}

func TestGetLocalRepoBranch(t *testing.T) {
	t.Parallel()
	branch, err := getLocalRepoBranch("../../")
	require.NoError(t, err, branch)
	require.NotEmpty(t, branch)
}
