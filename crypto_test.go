package main

import (
	"encoding/base64"
	"testing"
)

func TestCheckSignature(t *testing.T) {
	type test struct {
		algo       SigningAlgorithm
		pubKeyType KeyType
		pubKeyPem  string
		sigMsg     string
		sigB64     string
		valid      bool
	}
	tests := []test{
		{ // valid sha256
			algo:       RSASHA256,
			pubKeyType: RSA,
			pubKeyPem: `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDbWwz3qLQ704joFK0xYnK3VAo7
zBIlR3U+xoTL4C6B2l2tvPVxLtVPzsw3qKQCAIRpbZTop8QowqCzGzmxLlVu6G2w
tmEHG4D01Ls0FQIn5eoTbU6BdvEZrGQiGj6liXob62ErWMBOj2ginxYWZuXbLEeX
wJm6cutA66DtZ5QyhwIDAQAB
-----END PUBLIC KEY-----`,
			sigMsg: "This is a test.",
			sigB64: "ZqQfbVk2lkvoHmTCaCY/cdJYEKABuCpMeEKIV62rwcirG6hYFDW+YoDqmmjgfTwKA2jqehqnKk+LK+1pJI0OS4V+ecc5bHDozgTs0HVxFq4Bh7N1dtBvGGED4EfVFabVmntjJbt9btsMhg6VJ94rKaJHQZgHosMOjtIZ6TX32Fw=",
			valid:  true,
		},
		{ // invalid msg sha256
			algo:       RSASHA256,
			pubKeyType: RSA,
			pubKeyPem: `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDbWwz3qLQ704joFK0xYnK3VAo7
zBIlR3U+xoTL4C6B2l2tvPVxLtVPzsw3qKQCAIRpbZTop8QowqCzGzmxLlVu6G2w
tmEHG4D01Ls0FQIn5eoTbU6BdvEZrGQiGj6liXob62ErWMBOj2ginxYWZuXbLEeX
wJm6cutA66DtZ5QyhwIDAQAB
-----END PUBLIC KEY-----`,
			sigMsg: "This is a test. Modified",
			sigB64: "ZqQfbVk2lkvoHmTCaCY/cdJYEKABuCpMeEKIV62rwcirG6hYFDW+YoDqmmjgfTwKA2jqehqnKk+LK+1pJI0OS4V+ecc5bHDozgTs0HVxFq4Bh7N1dtBvGGED4EfVFabVmntjJbt9btsMhg6VJ94rKaJHQZgHosMOjtIZ6TX32Fw=",
			valid:  false,
		},
	}
	for _, test := range tests {
		sig, err := base64.StdEncoding.DecodeString(test.sigB64)
		if err != nil {
			t.Fatalf("failed to decode base64 (%#v)\n", err)
		}
		err = checkSignature(test.algo, test.pubKeyType, test.pubKeyPem, test.sigMsg, sig)
		if err != nil && test.valid {
			t.Fatalf("expected valid result for (\n%#v\n) got (%#v)\n", test, err)
		} else if err == nil && !test.valid {
			t.Fatalf("expected invalid result for (\n%#v\n) got (%#v)\n", test, err)
		}
	}
}
