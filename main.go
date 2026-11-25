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

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	sl "github.com/SENERGY-Platform/go-service-base/struct-logger"
	"github.com/SENERGY-Platform/mgw-sni-router/pkg/api"
	"github.com/SENERGY-Platform/mgw-sni-router/pkg/config"
	"github.com/SENERGY-Platform/mgw-sni-router/pkg/proxy"
	"github.com/SENERGY-Platform/mgw-sni-router/pkg/registry"
)

func main() {
	configPath := flag.String("config", "", "optional json configuration file; environment variables take precedence")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "unable to load config:", err)
		os.Exit(1)
	}
	logger := sl.New(cfg.Logger, os.Stderr, "github.com/SENERGY-Platform", "mgw-sni-router")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	reg := registry.New(time.Duration(cfg.RouteTTL))
	resolver := func(port func(registry.Registration) int) proxy.Resolver {
		return func(name string) (netip.AddrPort, bool) { return reg.Lookup(name, port) }
	}
	proxies := []*proxy.Proxy{
		{Name: "http", Sniff: proxy.SniffHTTP, Resolve: resolver(registry.HttpPort)},
		{Name: "https", Sniff: proxy.SniffTLS, Resolve: resolver(registry.HttpsPort)},
	}
	ports := []int{cfg.HttpPort, cfg.HttpsPort}

	listeners := make([]net.Listener, len(proxies))
	for i, p := range proxies {
		p.PeekTimeout = time.Duration(cfg.PeekTimeout)
		p.DialTimeout = time.Duration(cfg.DialTimeout)
		p.Logger = logger
		listeners[i], err = net.Listen("tcp", ":"+strconv.Itoa(ports[i]))
		if err != nil {
			logger.Error("unable to listen", "listener", p.Name, "port", ports[i], "error", err)
			os.Exit(1)
		}
	}
	apiServer := &http.Server{
		Addr:              ":" + strconv.Itoa(cfg.ApiPort),
		Handler:           api.New(reg, api.DialAlive(time.Duration(cfg.DialTimeout)), logger),
		ReadHeaderTimeout: 10 * time.Second,
	}

	var wg sync.WaitGroup
	errCh := make(chan error, len(proxies)+1)
	for i, p := range proxies {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := p.Serve(ctx, listeners[i]); err != nil {
				errCh <- fmt.Errorf("%s listener: %w", p.Name, err)
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := apiServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("api server: %w", err)
		}
	}()
	logger.Info("started", "http_port", cfg.HttpPort, "https_port", cfg.HttpsPort, "api_port", cfg.ApiPort)

	exitCode := 0
	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	case err = <-errCh:
		logger.Error("stopping after failure", "error", err)
		exitCode = 1
		stop()
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = apiServer.Shutdown(shutdownCtx)
	wg.Wait()
	os.Exit(exitCode)
}
