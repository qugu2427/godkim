package main

import (
	"fmt"
	"net"
	"testing"

	"github.com/foxcpp/go-mockdns"
)

func TestSign(t *testing.T) {

	var exampleOrgPrivKey string = `-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBALQcfOumlRZI4t1Wuk1rm4x0lDIHd2Lu58Lwk5CHq5w+UScq5A10
4PrXQ4dUL6R8mgTmizNE0oOXXM4nPA0PvysCAwEAAQJAe3sofdr4TY3s03i5Q4jp
3LK0Q1RxGkfWZwTO9oC9O+EnWeFX0ZwtIfjP0WV5gGh+T1epg1tqMn85zbU5TLe8
IQIhAPuUgsTT2zvjSqWqKQTicQeoVRfQ+2WijWFf4+si0i1xAiEAt0aLPJorVDUp
ACWT/J//CGlgaAi+TCtj/dRtSloHGFsCIDU5aSUNER+taXh89GqlIXaWRVJhkx4g
crq8F7MCTebxAiEAl4P2cC90SrV4I+rtIRiUmrujO96elBH7JEmN4L30x6kCIQDV
Fl1FBwbvEE36bmwARayL0xAFxNrtfR6HbuUyEqIQqQ==
-----END RSA PRIVATE KEY-----`

	var dnsMock map[string]mockdns.Zone = map[string]mockdns.Zone{
		"example.org.": {},
		"dkim._domainkey.example.org.": {
			TXT: []string{"v=DKIM1; k=rsa; p=MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALQcfOumlRZI4t1Wuk1rm4x0lDIHd2Lu58Lwk5CHq5w+UScq5A104PrXQ4dUL6R8mgTmizNE0oOXXM4nPA0PvysCAwEAAQ=="},
		},
	}

	srv, _ := mockdns.NewServer(dnsMock, false)
	defer srv.Close()
	srv.PatchNet(net.DefaultResolver)
	defer mockdns.UnpatchNet(net.DefaultResolver)

	type test struct {
		signPayload SignPayload
		valid       bool
	}

	tests := []test{
		{ // very basic valid message
			SignPayload{
				"MIME-Version: 1.0\r\nDate: Fri, 24 May 2024 10:19:18 -0600\r\nReply-To: John.Doe@example.org\r\nSubject: Test Email\r\nFrom: John Doe <John.Doe@example.org>\r\nTo: alice@colorado.edu\r\nContent-Type: multipart/alternative; boundary=\"00000000000095c7110619358760\"\r\n\r\n--00000000000095c7110619358760\r\nContent-Type: text/plain; charset=\"UTF-8\"\r\n\r\nthis is a test email\r\n\r\n--00000000000095c7110619358760\r\nContent-Type: text/html; charset=\"UTF-8\"\r\n\r\n<div dir=\"ltr\">this is a test email</div>\r\n\r\n--00000000000095c7110619358760--",
				"example.org",
				"dkim",
				DefaultHeaders,
				exampleOrgPrivKey,
			},
			true,
		},
	}

	for _, test := range tests {
		signedMail, err := test.signPayload.Sign()
		if test.valid && err != nil {
			t.Fatalf("unexpected err '%s' on payload %#v\n", err, test.signPayload)
		}
		results, err := Verify(signedMail)
		fmt.Printf("%s\n", results)
		if test.valid && err != nil {
			t.Fatalf("unexpected verify err '%s' on message: \n%#v\n", err, signedMail)
		}
		fmt.Printf("\n\n%#v\n\n", signedMail)
	}

}
