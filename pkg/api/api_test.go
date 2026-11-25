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

package api

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/SENERGY-Platform/mgw-sni-router/pkg/registry"
)

func post(h http.Handler, remote, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/routes", strings.NewReader(body))
	req.RemoteAddr = remote
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestRegisterUsesSourceAddress(t *testing.T) {
	reg := registry.New(time.Minute)
	h := New(reg, func(context.Context, registry.Route) bool { return true }, slog.New(slog.DiscardHandler))

	rec := post(h, "172.18.0.5:51234", `{"hosts":["syrconnect.de"],"http_port":80,"https_port":443,"default":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	got, ok := reg.Lookup("syrconnect.de", registry.HttpsPort)
	if !ok || got.String() != "172.18.0.5:443" {
		t.Errorf("Lookup = %v, %v", got, ok)
	}

	if rec = post(h, "172.18.0.6:40000", `{"hosts":["syrconnect.de"],"https_port":443}`); rec.Code != http.StatusConflict {
		t.Errorf("conflicting host: status %d", rec.Code)
	}
	if rec = post(h, "172.18.0.6:40000", `{"hosts":["x.example"]}`); rec.Code != http.StatusBadRequest {
		t.Errorf("registration without port: status %d", rec.Code)
	}
	if rec = post(h, "172.18.0.6:40000", `{"hosts":["x.example"],"https_port":443,"backend":"10.0.0.1"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown field: status %d", rec.Code)
	}
}

func TestRegisterReplacesUnreachableHolder(t *testing.T) {
	reg := registry.New(time.Minute)
	alive := map[string]bool{"172.18.0.5": false, "172.18.0.7": true}
	h := New(reg, func(_ context.Context, r registry.Route) bool { return alive[r.Backend.String()] }, slog.New(slog.DiscardHandler))

	body := `{"hosts":["syrconnect.de"],"http_port":80,"https_port":443,"default":true}`
	if rec := post(h, "172.18.0.5:1000", body); rec.Code != http.StatusOK {
		t.Fatalf("first registration: status %d", rec.Code)
	}
	// Module recreated with a new address; the old one is gone.
	if rec := post(h, "172.18.0.6:1000", body); rec.Code != http.StatusOK {
		t.Fatalf("re-registration after restart: status %d: %s", rec.Code, rec.Body)
	}
	got, _ := reg.Lookup("syrconnect.de", registry.HttpsPort)
	if got.String() != "172.18.0.6:443" {
		t.Errorf("Lookup = %v, want new address", got)
	}
	// A live holder keeps its hosts.
	if rec := post(h, "172.18.0.7:1000", `{"hosts":["cloud.example.com"],"https_port":443}`); rec.Code != http.StatusOK {
		t.Fatal(rec.Body)
	}
	alive["172.18.0.6"] = true
	if rec := post(h, "172.18.0.8:1000", `{"hosts":["cloud.example.com"],"https_port":443}`); rec.Code != http.StatusConflict {
		t.Errorf("live holder replaced: status %d", rec.Code)
	}
}
