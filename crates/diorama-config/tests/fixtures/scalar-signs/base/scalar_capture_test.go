package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestdioramaCapture(t *testing.T) {
	out := map[string]any{}
	for _, scalar := range []string{"--5", "+-5", "-+5", "0x-10", "-0b-1", "--170141183460469231731687303715884105728", "+0x-10", "+5", "0x10", "-0x10"} {
		fields := map[string]any{}
		for _, field := range []string{"string", "integer", "explicit_integer"} {
			input := "d2k: {namespace: " + scalar + "}\n"
			if field == "integer" {
				input = "network: {mtu: " + scalar + "}\n"
			}
			if field == "explicit_integer" {
				input = "network: {mtu: !!int " + scalar + "}\n"
			}
			path := filepath.Join(t.TempDir(), "config.yaml")
			if e := os.WriteFile(path, []byte(input), 0600); e != nil {
				t.Fatal(e)
			}
			c := Defaults()
			_, _, e := Read(path, c)
			message := ""
			if e != nil {
				message = e.Error()
			}
			fields[field] = map[string]any{"namespace": c.D2K.Namespace, "mtu": c.Network.MTU, "error": message}
		}
		out[scalar] = fields
	}
	data, e := json.Marshal(out)
	if e != nil {
		t.Fatal(e)
	}
	fmt.Printf("diorama_CAPTURE %s\n", data)
}
