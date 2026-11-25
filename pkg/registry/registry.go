/*
 * Copyright (c) 2026 InfAI (CC SES)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Package registry holds the routes that modules register at runtime. A route
// belongs to the IP address it was registered from and expires unless it is
// renewed within the TTL, so a restarted or removed module drops out on its
// own.
package registry

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

const maxHosts = 64

var ErrConflict = errors.New("conflict")
var ErrInvalid = errors.New("invalid registration")

// ConflictError names the live route that holds a requested host or the
// default role.
type ConflictError struct {
	Holder Route
	reason string
}

func (e *ConflictError) Error() string { return "conflict: " + e.reason }
func (e *ConflictError) Unwrap() error { return ErrConflict }

type Registration struct {
	// Hostnames matched against the TLS server name and the HTTP Host header.
	Hosts []string `json:"hosts"`
	// Port the backend serves plain HTTP on. 0 disables HTTP for this backend.
	HttpPort int `json:"http_port"`
	// Port the backend serves TLS on. 0 disables TLS for this backend.
	HttpsPort int `json:"https_port"`
	// Receives connections that carry no known server name or Host header.
	Default bool `json:"default"`
}

type Route struct {
	Registration
	Backend netip.Addr `json:"backend"`
	Expires time.Time  `json:"expires"`
}

type Registry struct {
	ttl    time.Duration
	now    func() time.Time
	mu     sync.Mutex
	routes map[netip.Addr]Route
}

func New(ttl time.Duration) *Registry {
	return &Registry{ttl: ttl, now: time.Now, routes: make(map[netip.Addr]Route)}
}

// Register stores or replaces the route of backend. A host or the default
// role that another live backend holds yields ErrConflict.
func (r *Registry) Register(backend netip.Addr, reg Registration) (Route, error) {
	reg, err := normalize(reg)
	if err != nil {
		return Route{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.prune()
	for addr, other := range r.routes {
		if addr == backend {
			continue
		}
		if reg.Default && other.Default {
			return Route{}, &ConflictError{Holder: other, reason: fmt.Sprintf("default backend is held by %s", addr)}
		}
		for _, h := range reg.Hosts {
			for _, oh := range other.Hosts {
				if h == oh {
					return Route{}, &ConflictError{Holder: other, reason: fmt.Sprintf("host %q is held by %s", h, addr)}
				}
			}
		}
	}
	route := Route{Registration: reg, Backend: backend, Expires: r.now().Add(r.ttl)}
	r.routes[backend] = route
	return route, nil
}

// Remove drops route, unless its backend has renewed it since route was read.
func (r *Registry) Remove(route Route) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if cur, ok := r.routes[route.Backend]; ok && cur.Expires.Equal(route.Expires) {
		delete(r.routes, route.Backend)
	}
}

// Lookup returns the backend address for host on the port chosen by port.
// An empty or unknown host falls back to the default backend.
func (r *Registry) Lookup(host string, port func(Registration) int) (netip.AddrPort, bool) {
	host = normalizeHost(host)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.prune()
	var fallback *Route
	for _, route := range r.routes {
		if host != "" {
			for _, h := range route.Hosts {
				if h == host {
					return addrPort(route, port)
				}
			}
		}
		if route.Default {
			fallback = &route
		}
	}
	if fallback == nil {
		return netip.AddrPort{}, false
	}
	return addrPort(*fallback, port)
}

func (r *Registry) List() []Route {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.prune()
	list := make([]Route, 0, len(r.routes))
	for _, route := range r.routes {
		list = append(list, route)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Backend.Less(list[j].Backend) })
	return list
}

func HttpPort(reg Registration) int  { return reg.HttpPort }
func HttpsPort(reg Registration) int { return reg.HttpsPort }

func addrPort(route Route, port func(Registration) int) (netip.AddrPort, bool) {
	p := port(route.Registration)
	if p == 0 {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(route.Backend, uint16(p)), true
}

// prune drops expired routes. The caller holds r.mu.
func (r *Registry) prune() {
	now := r.now()
	for addr, route := range r.routes {
		if !now.Before(route.Expires) {
			delete(r.routes, addr)
		}
	}
}

func normalize(reg Registration) (Registration, error) {
	if len(reg.Hosts) == 0 && !reg.Default {
		return reg, fmt.Errorf("%w: neither hosts nor default given", ErrInvalid)
	}
	if len(reg.Hosts) > maxHosts {
		return reg, fmt.Errorf("%w: more than %d hosts", ErrInvalid, maxHosts)
	}
	if reg.HttpPort == 0 && reg.HttpsPort == 0 {
		return reg, fmt.Errorf("%w: neither http_port nor https_port given", ErrInvalid)
	}
	for _, p := range []int{reg.HttpPort, reg.HttpsPort} {
		if p < 0 || p > 65535 {
			return reg, fmt.Errorf("%w: port %d out of range", ErrInvalid, p)
		}
	}
	hosts := make([]string, 0, len(reg.Hosts))
	seen := make(map[string]bool, len(reg.Hosts))
	for _, h := range reg.Hosts {
		n := normalizeHost(h)
		if !validHost(n) {
			return reg, fmt.Errorf("%w: host %q", ErrInvalid, h)
		}
		if !seen[n] {
			seen[n] = true
			hosts = append(hosts, n)
		}
	}
	reg.Hosts = hosts
	return reg, nil
}

func normalizeHost(h string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
}

func validHost(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
