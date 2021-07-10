/*
Copyright 2015 Gravitational, Inc.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package utils

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/gravitational/trace"
)

// NetAddr is network address that includes network, optional path and
// host port
type NetAddr struct {
	// Addr is the host:port address, like "localhost:22"
	Addr string `json:"addr"`
	// AddrNetwork is the type of a network socket, like "tcp" or "unix"
	AddrNetwork string `json:"network,omitempty"`
	// Path is a socket file path, like '/var/path/to/socket' in "unix:///var/path/to/socket"
	Path string `json:"path,omitempty"`
}

// Host returns host part of address without port
func (a *NetAddr) Host() string {
	host, _, err := net.SplitHostPort(a.Addr)
	if err == nil {
		return host
	}
	// this is done to remove optional square brackets
	if ip := net.ParseIP(strings.Trim(a.Addr, "[]")); len(ip) != 0 {
		return ip.String()
	}
	return a.Addr
}

// Port returns defaultPort if no port is set or is invalid,
// the real port otherwise
func (a *NetAddr) Port(defaultPort int) int {
	_, port, err := net.SplitHostPort(a.Addr)
	if err != nil {
		return defaultPort
	}
	porti, err := strconv.Atoi(port)
	if err != nil {
		return defaultPort
	}
	return porti
}

// IsLocal returns true if this is a local address
func (a *NetAddr) IsLocal() bool {
	host, _, err := net.SplitHostPort(a.Addr)
	if err != nil {
		return false
	}
	return IsLocalhost(host)
}

// IsLoopback returns true if this is a loopback address
func (a *NetAddr) IsLoopback() bool {
	return IsLoopback(a.Addr)
}

// IsEmpty returns true if address is empty
func (a *NetAddr) IsEmpty() bool {
	return a == nil || (a.Addr == "" && a.AddrNetwork == "" && a.Path == "")
}

// FullAddress returns full address including network and address (tcp://0.0.0.0:1243)
func (a *NetAddr) FullAddress() string {
	return fmt.Sprintf("%v://%v", a.AddrNetwork, a.Addr)
}

// String returns address without network (0.0.0.0:1234)
func (a *NetAddr) String() string {
	return a.Addr
}

// Network returns the scheme for this network address (tcp or unix)
func (a *NetAddr) Network() string {
	return a.AddrNetwork
}

// MarshalYAML defines how a network address should be marshalled to a string
func (a *NetAddr) MarshalYAML() (interface{}, error) {
	url := url.URL{Scheme: a.AddrNetwork, Host: a.Addr, Path: a.Path}
	return strings.TrimLeft(url.String(), "/"), nil
}

// UnmarshalYAML defines how a string can be unmarshalled into a network address
func (a *NetAddr) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var addr string
	err := unmarshal(&addr)
	if err != nil {
		return err
	}

	parsedAddr, err := ParseAddr(addr)
	if err != nil {
		return err
	}

	*a = *parsedAddr
	return nil
}

func (a *NetAddr) Set(s string) error {
	v, err := ParseAddr(s)
	if err != nil {
		return trace.Wrap(err)
	}
	a.Addr = v.Addr
	a.AddrNetwork = v.AddrNetwork
	return nil
}

// NetAddrsToStrings takes a list of netAddrs and returns a list of address strings.
func NetAddrsToStrings(netAddrs []NetAddr) []string {
	addrs := make([]string, len(netAddrs))
	for i, addr := range netAddrs {
		addrs[i] = addr.String()
	}
	return addrs
}

// ParseAddrs parses the provided slice of strings as a slice of NetAddr's.
func ParseAddrs(addrs []string) (result []NetAddr, err error) {
	for _, addr := range addrs {
		parsed, err := ParseAddr(addr)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		result = append(result, *parsed)
	}
	return result, nil
}

// ParseAddr takes strings like "tcp://host:port/path" and returns
// *NetAddr or an error
func ParseAddr(a string) (*NetAddr, error) {
	if a == "" {
		return nil, trace.BadParameter("missing parameter address")
	}
	if !strings.Contains(a, "://") {
		a = "tcp://" + a
	}
	u, err := url.Parse(a)
	if err != nil {
		return nil, trace.BadParameter("failed to parse %q: %v", a, err)
	}
	switch u.Scheme {
	case "tcp":
		return &NetAddr{Addr: u.Host, AddrNetwork: u.Scheme, Path: u.Path}, nil
	case "unix":
		return &NetAddr{Addr: u.Path, AddrNetwork: u.Scheme}, nil
	case "http", "https":
		return &NetAddr{Addr: u.Host, AddrNetwork: u.Scheme, Path: u.Path}, nil
	default:
		return nil, trace.BadParameter("'%v': unsupported scheme: '%v'", a, u.Scheme)
	}
}

// IsLocalhost returns true if this is a local hostname or ip
func IsLocalhost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip.IsLoopback() || ip.IsUnspecified()
}

// IsLoopback returns 'true' if a given hostname resolves to local
// host's loopback interface
func IsLoopback(host string) bool {
	if strings.Contains(host, ":") {
		var err error
		host, _, err = net.SplitHostPort(host)
		if err != nil {
			return false
		}
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return false
	}
	for _, ip := range ips {
		if ip.IsLoopback() {
			return true
		}
	}
	return false
}
