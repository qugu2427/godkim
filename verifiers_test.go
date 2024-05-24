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

// var dnsMock map[string]mockdns.Zone = map[string]mockdns.Zone{
// 	"test.domain.": {},
// 	"dkim._domainkey.test.domain.": {
// 		TXT: []string{"v=DKIM1; k=rsa; p=MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALQcfOumlRZI4t1Wuk1rm4x0lDIHd2Lu58Lwk5CHq5w+UScq5A104PrXQ4dUL6R8mgTmizNE0oOXXM4nPA0PvysCAwEAAQ=="},
// 	},
// }

// func TestVerify(t *testing.T) {
// 	srv, _ := mockdns.NewServer(dnsMock, false)
// 	defer srv.Close()
// 	srv.PatchNet(net.DefaultResolver)
// 	defer mockdns.UnpatchNet(net.DefaultResolver)

// 	type test struct {
// 		rawEmail    string
// 		expectedErr bool
// 	}

// 	tests := []test{
// 		{
// 			// DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=test.domain; h=a-header:b-header:c-header:from; s=dkim; bh=wE7NXSkgnx9PGiavN4OZhJztvkqPDlemV3OGuEnLwNo=; b=;\r\n
// 			// This is a test message.\r\n (wE7NXSkgnx9PGiavN4OZhJztvkqPDlemV3OGuEnLwNo=)
// 			// a-header:1.0\r\nb-header:abcD\t\nc-header:Some Thing\r\nfrom:John Doe <John.Doe@test.domain>\r\ndkim-signature:v=1; a=rsa-sha256; c=relaxed/relaxed; d=test.domain; h=a-header:b-header:c-header:from; s=dkim; bh=wE7NXSkgnx9PGiavN4OZhJztvkqPDlemV3OGuEnLwNo=; b=4Wq12AkqIfxE/fAGgoTdYjFW9dOVYEKd8c/LqdovFRg=
// 			"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=test.domain; h=a-header:b-header:c-header:from; s=dkim; bh=wE7NXSkgnx9PGiavN4OZhJztvkqPDlemV3OGuEnLwNo=; b=+S3BH+jhbISQIIIFpXTI1RUrPfZ0XRh4Yb5k0JAoVYg=;\r\nA-Header: 1.0\r\bB-Header: abcD\r\bC-Header: Some Thing\r\nFrom:John Doe <John.Doe@test.domain>\r\n\r\nThis is a test message.\r\n.\r\n",
// 			false,
// 		},
// 	}

// 	for _, test := range tests {
// 		res, err := Verify(test.rawEmail)
// 		for _, ress := range res {
// 			fmt.Println(ress)
// 		}
// 		if err != nil && !test.expectedErr {
// 			t.Fatalf("email %#v resulted in err '%s' expected no err\nresult=%#v\n", test.rawEmail, err, res)
// 		}
// 	}
// }
