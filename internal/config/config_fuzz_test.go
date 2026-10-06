package config

import (
	"bytes"
	"testing"

	"gopkg.in/yaml.v3"
)

func FuzzYAMLConfigValidation(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte("nodeName: node-a\n"),
		[]byte("heartbeat:\n  interval: 1s\n  timeout: 5s\n"),
		[]byte("pinRoot: /sys/fs/bpf/oncache/v1\n"),
		[]byte("{}\n"),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		cfg := defaults()
		decoder := yaml.NewDecoder(bytes.NewReader(data))
		decoder.KnownFields(true)
		if err := decoder.Decode(&cfg); err != nil {
			return
		}
		_ = cfg.Validate()
	})
}
