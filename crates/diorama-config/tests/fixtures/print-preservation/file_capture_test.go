package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sigs.k8s.io/yaml"
	"testing"
)

func TestdioramaCapture(t *testing.T) {
	cases := map[string]string{
		"empty-path":       "{\"path\": \"\"}",
		"empty-sans":       "{\"kubernetes\": {\"apiServer\": {\"extraSANs\": []}}}",
		"space-ls":         "{\"d2k\": {\"namespace\": \" \\u2028aa\"}}",
		"space-ps":         "{\"d2k\": {\"namespace\": \" \\u2029aa\"}}",
		"leading-ls-space": "{\"d2k\": {\"namespace\": \"\\u2028\\n a\"}}",
		"leading-ps-space": "{\"d2k\": {\"namespace\": \"\\u2029\\n a\"}}",
	}
	out := map[string]any{}
	for id, input := range cases {
		path := filepath.Join(t.TempDir(), "input.yaml")
		if err := os.WriteFile(path, []byte(input), 0600); err != nil {
			t.Fatal(err)
		}
		cfg := Defaults()
		_, _, err := Read(path, cfg)
		if err != nil {
			t.Fatal(err)
		}
		printed, err := yaml.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		out[id] = map[string]any{"path": cfg.Path, "namespace": cfg.D2K.Namespace, "extraSANs": cfg.Kubernetes.APIServer.ExtraSANs, "printed": string(printed)}
	}
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("diorama_CAPTURE " + string(b))
}
