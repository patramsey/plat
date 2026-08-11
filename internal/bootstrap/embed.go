package bootstrap

import _ "embed"

//go:embed dns.json
var embedded []byte

//go:embed ipv4.json
var embeddedIPv4 []byte

//go:embed ipv6.json
var embeddedIPv6 []byte

//go:embed asn.json
var embeddedASN []byte
