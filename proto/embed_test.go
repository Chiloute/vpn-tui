package proto

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const base = "https://github.com/Chiloute/vpn-tui/proto/rpc.schema.json"

func compile(t *testing.T, def string) *jsonschema.Schema {
	t.Helper()
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(Schema))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	if err := c.AddResource(base, doc); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile(base + "#/$defs/" + def)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSchema(t *testing.T) {
	key := strings.Repeat("A", 43) + "="
	cases := []struct {
		name, def, msg string
		ok             bool
	}{
		{"status", "request", `{"jsonrpc":"2.0","id":1,"method":"status"}`, true},
		{"unknown field", "request", `{"jsonrpc":"2.0","id":1,"method":"status","x":1}`, false},
		{"unknown method", "request", `{"jsonrpc":"2.0","id":1,"method":"nope"}`, false},
		{"bad id", "request", `{"jsonrpc":"2.0","id":1,"method":"up","params":{"id":"-Bad"}}`, false},
		{"up openvpn", "request", `{"jsonrpc":"2.0","id":2,"method":"up","params":{"id":"corp","secrets":{"username":"u","password":"p"}}}`, true},
		{"up wireguard", "request", `{"jsonrpc":"2.0","id":2,"method":"up","params":{"id":"wg1","secrets":{"private_key":"` + key + `"}}}`, true},
		{"up wireguard psk", "request", `{"jsonrpc":"2.0","id":2,"method":"up","params":{"id":"wg1","secrets":{"private_key":"` + key + `","preshared_key":"` + key + `"}}}`, true},
		{"up bad psk", "request", `{"jsonrpc":"2.0","id":2,"method":"up","params":{"id":"wg1","secrets":{"private_key":"` + key + `","preshared_key":"x"}}}`, false},
		{"up bad key", "request", `{"jsonrpc":"2.0","id":2,"method":"up","params":{"id":"wg1","secrets":{"private_key":"short"}}}`, false},
		{"secrets elsewhere", "request", `{"jsonrpc":"2.0","id":3,"method":"profile_delete","params":{"id":"a","secrets":{}}}`, false},
		{"event", "event_notification", `{"jsonrpc":"2.0","method":"event","params":{"time":"2026-01-02T03:04:05Z","profile":null,"state":"armed","kind":"up","detail":""}}`, true},
		{"error", "response", `{"jsonrpc":"2.0","id":1,"error":{"code":-32005,"message":"nf"}}`, true},
		{"color base0D", "color", `"base0D"`, true},
		{"color hex", "color", `"#ff0000"`, false},
		{"color base10", "color", `"base10"`, false},
	}
	for _, c := range cases {
		var v any
		if err := json.Unmarshal([]byte(c.msg), &v); err != nil {
			t.Fatal(err)
		}
		if err := compile(t, c.def).Validate(v); (err == nil) != c.ok {
			t.Errorf("%s: ok=%v err=%v", c.name, c.ok, err)
		}
	}
}
