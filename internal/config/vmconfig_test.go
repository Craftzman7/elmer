package config

import (
	"path/filepath"
	"runtime"
	"testing"
)

// vm/elmer.yaml ships as the test-target configuration (see vm/README.md);
// it must stay loadable and keep the demo rule intact as the schema moves.
func TestVMTargetConfigLoads(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(file), "..", "..", "vm", "elmer.yaml")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load vm/elmer.yaml: %v", err)
	}
	if len(cfg.Rules) != 1 || cfg.Rules[0].ID != "flag-access" {
		t.Fatalf("expected the flag-access demo rule, got %+v", cfg.Rules)
	}
	for _, m := range []string{"ebpf", "process", "auth", "fim", "net", "persistence"} {
		if !cfg.MonitorEnabled(m) {
			t.Errorf("monitor %s should be enabled", m)
		}
	}
	var webWatched bool
	for _, p := range cfg.FIM.Paths {
		if p == "/var/www/" {
			webWatched = true
		}
	}
	if !webWatched {
		t.Error("fim.extra_paths /var/www/ did not make it into the watch set")
	}
}
