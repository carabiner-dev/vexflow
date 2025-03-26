// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"crypto/sha256"
	"fmt"
	"strings"

	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/openvex/go-vex/pkg/vex"
)

type Repository struct {
	Branches []Branch
}

type Branch struct {
	// Repository URL
	Repository string `json:"repo"`

	// Name is the branch we're tracking
	Name string `json:"name"`

	// TargetCommit is the commit where we'll operate on. If blank, then the last
	// in the branch will be used.
	TargetCommit string `json:"-"`

	// LastCommit is the last commit seen in the branc
	LastCommit string `json:"-"`

	// ClonePath points to a local copy of the branch
	ClonePath string `json:"-"`
}

// Identifier returns a URL that identifies the branch in the repo
func (b *Branch) Identifier() string {
	if b.Repository == "" || b.Name == "" {
		return ""
	}
	return fmt.Sprintf("%s@%s", b.Repository, b.Name)
}

func (b *Branch) Purl() string {
	if b.Identifier() == "" {
		return ""
	}
	return fmt.Sprintf("pkg:%s", strings.ReplaceAll(b.Identifier(), "github.com/", "github/"))
}

// ToLocator returns an SPDX CVS locator representing the branch
func (b *Branch) ToLocator() string {
	if b.Repository == "" || b.Name == "" {
		return ""
	}
	return fmt.Sprintf("git+https://%s@%s", b.Repository, b.Name)
}

// ToResourceDescriptor returns a representation of the branch as an intoto
// ResourceDescriptor suitable to use in an attestation.
func (b *Branch) ToResourceDescriptor() *intoto.ResourceDescriptor {
	h := sha256.New()
	h.Write([]byte(b.Identifier()))
	digest := fmt.Sprintf("%x", h.Sum(nil))

	return &intoto.ResourceDescriptor{
		Name: b.Identifier(),
		Uri:  b.ToLocator(),
		Digest: map[string]string{
			string(intoto.AlgorithmSHA256): digest,
		},
	}
}

// ToVexComponent converts the branch data to an OpenVEX component
// ready to use in the product of a statement.
func (b *Branch) ToVexComponent() *vex.Component {
	h := sha256.New()
	h.Write([]byte(b.Identifier()))
	digest := fmt.Sprintf("%x", h.Sum(nil))

	return &vex.Component{
		ID: b.Identifier(),
		Hashes: map[vex.Algorithm]vex.Hash{
			vex.SHA256: vex.Hash(digest),
		},
		Identifiers: map[vex.IdentifierType]string{
			vex.PURL: b.Purl(),
		},
	}
}
