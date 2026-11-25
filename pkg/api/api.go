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

// Package api serves the registration endpoint. The backend address of a
// route is the source address of the registering request, so a module does
// not need to know its own address on the container network.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/SENERGY-Platform/mgw-sni-router/pkg/registry"
)

const maxBody = 16 << 10

// Alive reports whether the backend of route still accepts connections.
type Alive func(ctx context.Context, route registry.Route) bool

// DialAlive tries the TLS port, then the HTTP port of route.
func DialAlive(timeout time.Duration) Alive {
	return func(ctx context.Context, route registry.Route) bool {
		d := net.Dialer{Timeout: timeout}
		for _, p := range []int{route.HttpsPort, route.HttpPort} {
			if p == 0 {
				continue
			}
			conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(route.Backend.String(), strconv.Itoa(p)))
			if err == nil {
				conn.Close()
				return true
			}
		}
		return false
	}
}

// New serves the registration API. A conflicting route whose backend no
// longer answers is replaced: a module recreated with a new address would
// otherwise wait for its own stale route to expire.
func New(reg *registry.Registry, alive Alive, logger *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /routes", func(w http.ResponseWriter, r *http.Request) {
		backend, err := sourceAddr(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var body registry.Registration
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
		dec.DisallowUnknownFields()
		if err = dec.Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		route, err := reg.Register(backend, body)
		var conflict *registry.ConflictError
		for i := 0; i < 4 && errors.As(err, &conflict); i++ {
			if alive(r.Context(), conflict.Holder) {
				break
			}
			logger.Info("replacing route of unreachable backend", "backend", conflict.Holder.Backend.String(), "by", backend.String())
			reg.Remove(conflict.Holder)
			route, err = reg.Register(backend, body)
		}
		switch {
		case errors.Is(err, registry.ErrInvalid):
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		case errors.Is(err, registry.ErrConflict):
			logger.Warn("registration rejected", "backend", backend.String(), "error", err)
			http.Error(w, err.Error(), http.StatusConflict)
			return
		case err != nil:
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		logger.Debug("route registered", "backend", backend.String(), "hosts", route.Hosts, "default", route.Default)
		writeJSON(w, route)
	})
	mux.HandleFunc("GET /routes", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, reg.List())
	})
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return mux
}

func sourceAddr(r *http.Request) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, err
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, err
	}
	return addr.Unmap().WithZone(""), nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
