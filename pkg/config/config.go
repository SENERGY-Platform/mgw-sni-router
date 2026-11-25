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

package config

import (
	"time"

	"github.com/SENERGY-Platform/go-service-base/config-hdl"
	"github.com/SENERGY-Platform/go-service-base/config-hdl/types"
	sl "github.com/SENERGY-Platform/go-service-base/struct-logger"
)

type Config struct {
	Logger      sl.Config      `json:"logger"`
	HttpPort    int            `json:"http_port" env_var:"HTTP_PORT"`
	HttpsPort   int            `json:"https_port" env_var:"HTTPS_PORT"`
	ApiPort     int            `json:"api_port" env_var:"API_PORT"`
	RouteTTL    types.Duration `json:"route_ttl" env_var:"ROUTE_TTL"`
	PeekTimeout types.Duration `json:"peek_timeout" env_var:"PEEK_TIMEOUT"`
	DialTimeout types.Duration `json:"dial_timeout" env_var:"DIAL_TIMEOUT"`
}

func Load(path string) (Config, error) {
	cfg := Config{
		Logger: sl.Config{
			Handler:    sl.JsonHandlerSelector,
			Level:      sl.LevelInfo,
			TimeFormat: time.RFC3339Nano,
			TimeUtc:    true,
			AddMeta:    true,
		},
		HttpPort:    80,
		HttpsPort:   443,
		ApiPort:     8080,
		RouteTTL:    types.Duration(90 * time.Second),
		PeekTimeout: types.Duration(10 * time.Second),
		DialTimeout: types.Duration(5 * time.Second),
	}
	err := config_hdl.Load(&cfg, nil, []config_hdl.EnvTypeParser{types.DurationEnvTypeParser}, nil, path)
	return cfg, err
}
