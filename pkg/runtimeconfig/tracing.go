package runtimeconfig

import (
	"errors"
	"strings"

	"github.com/spf13/pflag"
)

type TracingConfig struct {
	Enabled bool
	File    string
}

func (cfg TracingConfig) Validate() error {
	if cfg.Enabled && strings.TrimSpace(cfg.File) == "" {
		return errors.New("tracing.file is required when tracing.enabled is true")
	}
	return nil
}

func buildTracingConfig(flags *pflag.FlagSet, lookupEnv func(string) (string, bool)) (TracingConfig, error) {
	enabled, err := getBool(flags, lookupEnv, "tracing.enabled", "TRACING_ENABLED")
	if err != nil {
		return TracingConfig{}, err
	}
	file, _ := lookupEnv("TRACING_FILE")
	if flags.Changed("tracing.file") {
		file, err = flags.GetString("tracing.file")
		if err != nil {
			return TracingConfig{}, err
		}
	}
	cfg := TracingConfig{Enabled: enabled, File: file}
	return cfg, cfg.Validate()
}
