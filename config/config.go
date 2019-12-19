// Copyright 2018 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"fmt"
	"io/ioutil"
	"regexp"
	"time"

	"github.com/soniah/gosnmp"
	"gopkg.in/yaml.v2"
)

func LoadFile(filename string) (*Config, error) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	cfg := &Config{}
	err = yaml.UnmarshalStrict(content, cfg)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

var (
	DefaultAuth = Auth{
		Community:     "public",
		SecurityLevel: "noAuthNoPriv",
		AuthProtocol:  "MD5",
		PrivProtocol:  "DES",
	}
	DefaultWalkParams = WalkParams{
		Version:        2,
		MaxRepetitions: 25,
		Retries:        3,
		Timeout:        time.Second * 20,
		Auth:           DefaultAuth,
	}
	DefaultModule = Module{
		WalkParams: DefaultWalkParams,
	}
	DefaultRegexpExtract = RegexpExtract{
		Value: "$1",
	}
)

// Config for the snmp_exporter.
type Config map[string]*Module

type WalkParams struct {
	Version        int           `yaml:"version,omitempty" toml:"version"`
	MaxRepetitions uint8         `yaml:"max_repetitions,omitempty" toml:"max_repetitions"`
	Retries        int           `yaml:"retries,omitempty" toml:"retries"`
	Timeout        time.Duration `yaml:"timeout,omitempty" toml:"timeout"`
	Auth           Auth          `yaml:"auth,omitempty" toml:"auth"`
}

type Module struct {
	// A list of OIDs.
	Walk       []string   `yaml:"walk,omitempty" toml:"walk"`
	Get        []string   `yaml:"get,omitempty" toml:"get"`
	Metrics    []*Metric  `yaml:"metrics" toml:"metrics"`
	WalkParams WalkParams `yaml:",inline" toml:"walk_params"`
}

func (c *Module) Validate() error {
	wp := c.WalkParams

	if wp.Version < 1 || wp.Version > 3 {
		return fmt.Errorf("SNMP version must be 1, 2 or 3. Got: %d", wp.Version)
	}
	if wp.Version == 3 {
		switch wp.Auth.SecurityLevel {
		case "authPriv":
			if wp.Auth.PrivPassword == "" {
				return fmt.Errorf("priv password is missing, required for SNMPv3 with priv")
			}
			if wp.Auth.PrivProtocol != "DES" && wp.Auth.PrivProtocol != "AES" {
				return fmt.Errorf("priv protocol must be DES or AES")
			}
			fallthrough
		case "authNoPriv":
			if wp.Auth.Password == "" {
				return fmt.Errorf("auth password is missing, required for SNMPv3 with auth")
			}
			if wp.Auth.AuthProtocol != "MD5" && wp.Auth.AuthProtocol != "SHA" {
				return fmt.Errorf("auth protocol must be SHA or MD5")
			}
			fallthrough
		case "noAuthNoPriv":
			if wp.Auth.Username == "" {
				return fmt.Errorf("auth username is missing, required for SNMPv3")
			}
		default:
			return fmt.Errorf("security level must be one of authPriv, authNoPriv or noAuthNoPriv")
		}
	}
	return nil
}

func (c *Module) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*c = DefaultModule
	type plain Module
	if err := unmarshal((*plain)(c)); err != nil {
		return err
	}

	return c.Validate()
}

// ConfigureSNMP sets the various version and auth settings.
func (c WalkParams) ConfigureSNMP(g *gosnmp.GoSNMP) {
	switch c.Version {
	case 1:
		g.Version = gosnmp.Version1
	case 2:
		g.Version = gosnmp.Version2c
	case 3:
		g.Version = gosnmp.Version3
	}
	g.Community = string(c.Auth.Community)
	g.ContextName = c.Auth.ContextName

	// v3 security settings.
	g.SecurityModel = gosnmp.UserSecurityModel
	usm := &gosnmp.UsmSecurityParameters{
		UserName: c.Auth.Username,
	}
	auth, priv := false, false
	switch c.Auth.SecurityLevel {
	case "noAuthNoPriv":
		g.MsgFlags = gosnmp.NoAuthNoPriv
	case "authNoPriv":
		g.MsgFlags = gosnmp.AuthNoPriv
		auth = true
	case "authPriv":
		g.MsgFlags = gosnmp.AuthPriv
		auth = true
		priv = true
	}
	if auth {
		usm.AuthenticationPassphrase = string(c.Auth.Password)
		switch c.Auth.AuthProtocol {
		case "SHA":
			usm.AuthenticationProtocol = gosnmp.SHA
		case "MD5":
			usm.AuthenticationProtocol = gosnmp.MD5
		}
	}
	if priv {
		usm.PrivacyPassphrase = string(c.Auth.PrivPassword)
		switch c.Auth.PrivProtocol {
		case "DES":
			usm.PrivacyProtocol = gosnmp.DES
		case "AES":
			usm.PrivacyProtocol = gosnmp.AES
		}
	}
	g.SecurityParameters = usm
}

type Metric struct {
	Name           string                     `yaml:"name" toml:"name"`
	Oid            string                     `yaml:"oid" toml:"oid"`
	Type           string                     `yaml:"type" toml:"type"`
	Help           string                     `yaml:"help" toml:"help"`
	Indexes        []*Index                   `yaml:"indexes,omitempty" toml:"indexes"`
	Lookups        []*Lookup                  `yaml:"lookups,omitempty" toml:"lookups"`
	RegexpExtracts map[string][]RegexpExtract `yaml:"regex_extracts,omitempty" toml:"regex_extracts"`
	EnumValues     map[int]string             `yaml:"enum_values,omitempty" toml:"enum_values"`
}

type Index struct {
	Labelname string `yaml:"labelname" toml:"labelname"`
	Type      string `yaml:"type" toml:"type"`
	FixedSize int    `yaml:"fixed_size,omitempty" toml:"fixed_size"`
	Implied   bool   `yaml:"implied,omitempty" toml:"implied"`
}

type Lookup struct {
	Labels    []string `yaml:"labels" toml:"labels"`
	Labelname string   `yaml:"labelname" toml:"labelname"`
	Oid       string   `yaml:"oid,omitempty" toml:"oid"`
	Type      string   `yaml:"type,omitempty" toml:"type"`
}

// Secret is a string that must not be revealed on marshaling.
type Secret string

// Hack for creating snmp.yml with the secret.
var (
	DoNotHideSecrets = false
)

// MarshalYAML implements the yaml.Marshaler interface.
func (s Secret) MarshalYAML() (interface{}, error) {
	if DoNotHideSecrets {
		return string(s), nil
	}
	if s != "" {
		return "<secret>", nil
	}
	return nil, nil
}

type Auth struct {
	Community     Secret `yaml:"community,omitempty" toml:"community"`
	SecurityLevel string `yaml:"security_level,omitempty" toml:"security_level"`
	Username      string `yaml:"username,omitempty" toml:"username"`
	Password      Secret `yaml:"password,omitempty" toml:"password"`
	AuthProtocol  string `yaml:"auth_protocol,omitempty" toml:"auth_protocol"`
	PrivProtocol  string `yaml:"priv_protocol,omitempty" toml:"priv_protocol"`
	PrivPassword  Secret `yaml:"priv_password,omitempty" toml:"priov_password"`
	ContextName   string `yaml:"context_name,omitempty" toml:"context_name"`
}

type RegexpExtract struct {
	Value string `yaml:"value" toml:"value"`
	Regex Regexp `yaml:"regex" toml:"regex"`
}

func (c *RegexpExtract) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*c = DefaultRegexpExtract
	type plain RegexpExtract
	if err := unmarshal((*plain)(c)); err != nil {
		return err
	}
	return nil
}

// Regexp encapsulates a regexp.Regexp and makes it YAML marshalable.
type Regexp struct {
	*regexp.Regexp
}

// MarshalYAML implements the yaml.Marshaler interface.
func (re Regexp) MarshalYAML() (interface{}, error) {
	if re.Regexp != nil {
		return re.String(), nil
	}
	return nil, nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (re *Regexp) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	regex, err := regexp.Compile("^(?:" + s + ")$")
	if err != nil {
		return err
	}
	re.Regexp = regex
	return nil
}
