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

package registry

import (
	"errors"
	"net/netip"
	"testing"
	"time"
)

var (
	syr   = netip.MustParseAddr("172.18.0.5")
	other = netip.MustParseAddr("172.18.0.6")
)

func newTestRegistry() (*Registry, *time.Time) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	r := New(90 * time.Second)
	r.now = func() time.Time { return now }
	return r, &now
}

func TestLookupByHostAndDefault(t *testing.T) {
	r, _ := newTestRegistry()
	if _, err := r.Register(syr, Registration{Hosts: []string{"SyrConnect.de.", "maintenance.syrconnect.de"}, HttpPort: 80, HttpsPort: 443, Default: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Register(other, Registration{Hosts: []string{"cloud.example.com"}, HttpsPort: 8443}); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		host string
		port func(Registration) int
		want string
		ok   bool
	}{
		{"syrconnect.de", HttpsPort, "172.18.0.5:443", true},
		{"MAINTENANCE.syrconnect.de", HttpPort, "172.18.0.5:80", true},
		{"cloud.example.com", HttpsPort, "172.18.0.6:8443", true},
		{"cloud.example.com", HttpPort, "", false}, // backend has no http port
		{"", HttpsPort, "172.18.0.5:443", true},    // no name: default
		{"unknown.example.com", HttpPort, "172.18.0.5:80", true},
	}
	for _, c := range cases {
		got, ok := r.Lookup(c.host, c.port)
		if ok != c.ok || (ok && got.String() != c.want) {
			t.Errorf("Lookup(%q) = %v, %v; want %v, %v", c.host, got, ok, c.want, c.ok)
		}
	}
}

func TestNoDefault(t *testing.T) {
	r, _ := newTestRegistry()
	if _, err := r.Register(other, Registration{Hosts: []string{"cloud.example.com"}, HttpsPort: 443}); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Lookup("", HttpsPort); ok {
		t.Error("lookup without name succeeded without a default backend")
	}
}

func TestConflicts(t *testing.T) {
	r, _ := newTestRegistry()
	if _, err := r.Register(syr, Registration{Hosts: []string{"syrconnect.de"}, HttpsPort: 443, Default: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Register(other, Registration{Hosts: []string{"SYRCONNECT.DE"}, HttpsPort: 443}); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate host: got %v, want ErrConflict", err)
	}
	if _, err := r.Register(other, Registration{Hosts: []string{"cloud.example.com"}, HttpsPort: 443, Default: true}); !errors.Is(err, ErrConflict) {
		t.Errorf("second default: got %v, want ErrConflict", err)
	}
	// The holder itself may renew and change its route.
	if _, err := r.Register(syr, Registration{Hosts: []string{"syrconnect.de", "firmware.syrconnect.de"}, HttpsPort: 443, Default: true}); err != nil {
		t.Errorf("renewal by holder: %v", err)
	}
}

func TestExpiry(t *testing.T) {
	r, now := newTestRegistry()
	if _, err := r.Register(syr, Registration{Hosts: []string{"syrconnect.de"}, HttpsPort: 443, Default: true}); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(89 * time.Second)
	if _, ok := r.Lookup("syrconnect.de", HttpsPort); !ok {
		t.Fatal("route expired before its ttl")
	}
	*now = now.Add(time.Second)
	if _, ok := r.Lookup("syrconnect.de", HttpsPort); ok {
		t.Fatal("route still served after its ttl")
	}
	// A restarted module gets a new address and may take over the hosts.
	if _, err := r.Register(other, Registration{Hosts: []string{"syrconnect.de"}, HttpsPort: 443, Default: true}); err != nil {
		t.Errorf("takeover after expiry: %v", err)
	}
}

func TestInvalid(t *testing.T) {
	r, _ := newTestRegistry()
	for name, reg := range map[string]Registration{
		"empty":        {HttpsPort: 443},
		"no port":      {Hosts: []string{"a.example"}},
		"port range":   {Hosts: []string{"a.example"}, HttpsPort: 70000},
		"bad host":     {Hosts: []string{"a b.example"}, HttpsPort: 443},
		"empty label":  {Hosts: []string{"a..example"}, HttpsPort: 443},
		"leading dash": {Hosts: []string{"-a.example"}, HttpsPort: 443},
	} {
		if _, err := r.Register(syr, reg); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: got %v, want ErrInvalid", name, err)
		}
	}
}
