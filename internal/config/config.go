// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
	"sigs.k8s.io/release-utils/util"
)

// Load reads and parses the vexflow configuration file
func Load(path string) (*Data, error) {
	if !util.Exists(path) {
		return nil, nil
	}
	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	ret := &Data{}
	if err := yaml.Unmarshal(data, ret); err != nil {
		return nil, fmt.Errorf("unmarshaling config file")
	}
	return ret, nil
}

type Data struct {
	Repositories []string `yaml:"repositories"`
}
