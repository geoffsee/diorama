package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"sigs.k8s.io/yaml"
)

func TestdioramaCapture(t *testing.T) {
	cases := map[string]string{
		"nel-double-literal":        "d2k: {namespace: \"a    b\"}\n",
		"nel-double-escaped":        "d2k: {namespace: \"a\\u0085    b\"}\n",
		"nel-single-literal":        "d2k: {namespace: 'a    b'}\n",
		"nel-plain":                 "d2k:\n  namespace: a    b\n",
		"nel-literal-block":         "d2k:\n  namespace: |\n    a    b\n",
		"nel-folded-block":          "d2k:\n  namespace: >\n    a    b\n",
		"nel-between-fields":        "logging: {debug: true}d2k: {namespace: ok}\n",
		"ls-double-literal":         "d2k: {namespace: \"a     b\"}\n",
		"ls-double-escaped":         "d2k: {namespace: \"a\\u2028    b\"}\n",
		"ls-single-literal":         "d2k: {namespace: 'a     b'}\n",
		"ls-plain":                  "d2k:\n  namespace: a     b\n",
		"ls-literal-block":          "d2k:\n  namespace: |\n    a     b\n",
		"ls-folded-block":           "d2k:\n  namespace: >\n    a     b\n",
		"ls-between-fields":         "logging: {debug: true} d2k: {namespace: ok}\n",
		"ps-double-literal":         "d2k: {namespace: \"a     b\"}\n",
		"ps-double-escaped":         "d2k: {namespace: \"a\\u2029    b\"}\n",
		"ps-single-literal":         "d2k: {namespace: 'a     b'}\n",
		"ps-plain":                  "d2k:\n  namespace: a     b\n",
		"ps-literal-block":          "d2k:\n  namespace: |\n    a     b\n",
		"ps-folded-block":           "d2k:\n  namespace: >\n    a     b\n",
		"ps-between-fields":         "logging: {debug: true} d2k: {namespace: ok}\n",
		"ls-explicit-block-indent":  "d2k:\n  namespace: |2\n      a       b\n",
		"ls-more-indented-block":    "d2k:\n  namespace: |\n    a       b\n",
		"ls-double-consecutive":     "d2k: {namespace: \"a      b\"}\n",
		"ls-trailing-strip":         "d2k:\n  namespace: |-\n    a \n",
		"ls-trailing-clip":          "d2k:\n  namespace: |\n    a \n",
		"ls-unicode-before":         "d2k: {namespace: \"雪     b\"}\n",
		"ls-escaped-marker":         "d2k: {namespace: \"\\uE000     \\U0000E001\"}\n",
		"ps-explicit-block-indent":  "d2k:\n  namespace: |2\n      a       b\n",
		"ps-more-indented-block":    "d2k:\n  namespace: |\n    a       b\n",
		"ps-double-consecutive":     "d2k: {namespace: \"a      b\"}\n",
		"ps-trailing-strip":         "d2k:\n  namespace: |-\n    a \n",
		"ps-trailing-clip":          "d2k:\n  namespace: |\n    a \n",
		"ps-unicode-before":         "d2k: {namespace: \"雪     b\"}\n",
		"ps-escaped-marker":         "d2k: {namespace: \"\\uE000     \\U0000E001\"}\n",
		"ls-continued":              "d2k: {namespace: \"a\\     b\"}\n",
		"ls-escaped-slash":          "d2k: {namespace: \"a\\\\     b\"}\n",
		"ls-keep-cr":                "d2k:\n  namespace: |+\n    a \r",
		"ls-keep-crlf":              "d2k:\n  namespace: |+\n    a \r\n",
		"ps-continued":              "d2k: {namespace: \"a\\     b\"}\n",
		"ps-escaped-slash":          "d2k: {namespace: \"a\\\\     b\"}\n",
		"ps-keep-cr":                "d2k:\n  namespace: |+\n    a \r",
		"ps-keep-crlf":              "d2k:\n  namespace: |+\n    a \r\n",
		"escaped-control-cr":        "{\"d2k\": {\"namespace\": \"a\\rb\"}}",
		"escaped-control-crlf":      "{\"d2k\": {\"namespace\": \"a\\r\\nb\"}}",
		"escaped-control-tab":       "{\"d2k\": {\"namespace\": \"a\\tb\"}}",
		"escaped-control-null":      "{\"d2k\": {\"namespace\": \"a\\u0000b\"}}",
		"escaped-control-bell":      "{\"d2k\": {\"namespace\": \"a\\u0007b\"}}",
		"escaped-control-nel-space": "{\"d2k\": {\"namespace\": \"a\\u0085 b\"}}",
		"escaped-control-ls-space":  "{\"d2k\": {\"namespace\": \"a\\u2028 b\"}}",
		"escaped-control-ps-space":  "{\"d2k\": {\"namespace\": \"a\\u2029 b\"}}",
		"nel-cr-before-block":       "d2k:\n  namespace: |+\n    a\r    b\n",
		"nel-cr-before-quoted":      "d2k: {namespace: \"a\r    b\"}\n",
		"ls-cr-before-block":        "d2k:\n  namespace: |+\n    a\r     b\n",
		"ls-cr-before-quoted":       "d2k: {namespace: \"a\r     b\"}\n",
		"ps-cr-before-block":        "d2k:\n  namespace: |+\n    a\r     b\n",
		"ps-cr-before-quoted":       "d2k: {namespace: \"a\r     b\"}\n",
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
		out[id] = map[string]any{"namespace": cfg.D2K.Namespace, "printed": string(printed)}
	}
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("diorama_CAPTURE " + string(b))
}
