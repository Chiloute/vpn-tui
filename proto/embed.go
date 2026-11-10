// Package proto embeds the JSON-RPC contract shared by daemon and client.
package proto

import _ "embed"

// Schema is the JSON Schema (draft 2020-12) of the RPC contract.
//
//go:embed rpc.schema.json
var Schema []byte
