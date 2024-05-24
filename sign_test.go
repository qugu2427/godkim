package main

/* priv key used for testing
-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBALQcfOumlRZI4t1Wuk1rm4x0lDIHd2Lu58Lwk5CHq5w+UScq5A10
4PrXQ4dUL6R8mgTmizNE0oOXXM4nPA0PvysCAwEAAQJAe3sofdr4TY3s03i5Q4jp
3LK0Q1RxGkfWZwTO9oC9O+EnWeFX0ZwtIfjP0WV5gGh+T1epg1tqMn85zbU5TLe8
IQIhAPuUgsTT2zvjSqWqKQTicQeoVRfQ+2WijWFf4+si0i1xAiEAt0aLPJorVDUp
ACWT/J//CGlgaAi+TCtj/dRtSloHGFsCIDU5aSUNER+taXh89GqlIXaWRVJhkx4g
crq8F7MCTebxAiEAl4P2cC90SrV4I+rtIRiUmrujO96elBH7JEmN4L30x6kCIQDV
Fl1FBwbvEE36bmwARayL0xAFxNrtfR6HbuUyEqIQqQ==
-----END RSA PRIVATE KEY-----
*/

// var pemKey string = "-----BEGIN RSA PRIVATE KEY-----
// MIIBOwIBAAJBALQcfOumlRZI4t1Wuk1rm4x0lDIHd2Lu58Lwk5CHq5w+UScq5A10
// 4PrXQ4dUL6R8mgTmizNE0oOXXM4nPA0PvysCAwEAAQJAe3sofdr4TY3s03i5Q4jp
// 3LK0Q1RxGkfWZwTO9oC9O+EnWeFX0ZwtIfjP0WV5gGh+T1epg1tqMn85zbU5TLe8
// IQIhAPuUgsTT2zvjSqWqKQTicQeoVRfQ+2WijWFf4+si0i1xAiEAt0aLPJorVDUp
// ACWT/J//CGlgaAi+TCtj/dRtSloHGFsCIDU5aSUNER+taXh89GqlIXaWRVJhkx4g
// crq8F7MCTebxAiEAl4P2cC90SrV4I+rtIRiUmrujO96elBH7JEmN4L30x6kCIQDV
// Fl1FBwbvEE36bmwARayL0xAFxNrtfR6HbuUyEqIQqQ==
// -----END RSA PRIVATE KEY-----"

// var dnsMock map[string]mockdns.Zone = map[string]mockdns.Zone{
// 	"example.org.": {},
// 	"dkim._domainkey.example.org.": {
// 		TXT: []string{"v=DKIM1; k=rsa; p=MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALQcfOumlRZI4t1Wuk1rm4x0lDIHd2Lu58Lwk5CHq5w+UScq5A104PrXQ4dUL6R8mgTmizNE0oOXXM4nPA0PvysCAwEAAQ=="},
// 	},
// }

// func TestSign(t *testing.T) {
// 	srv, _ := mockdns.NewServer(dnsMock, false)
// 	defer srv.Close()
// 	srv.PatchNet(net.DefaultResolver)
// 	defer mockdns.UnpatchNet(net.DefaultResolver)

// 	// Step 1: Decode the PEM string
// 	block, _ := pem.Decode([]byte(pemKey))
// 	if block == nil || block.Type != "RSA PRIVATE KEY" {
// 		fmt.Println("Failed to decode PEM block containing the key")
// 		return
// 	}

// 	// Step 2: Parse the decoded key
// 	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
// 	if err != nil {
// 		fmt.Println("Failed to parse RSA private key:", err)
// 		return
// 	}

// }
