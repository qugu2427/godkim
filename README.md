# GoDKIM
A go module for verifying email with DKIM as described by RFC 6376.
**WORK IN PROGRESS**

## Verify
`Verify(rawMail string)` returns a slice of verifications results with one result for each signature. Verify also returns an error when verification has failed.

Example Mail:
```go
package main

func main() {
    /*
    IMPORTANT NOTE!
    The email must be in its completely raw form!
    (including \r \n \t etc)
    */
    rawEmail := ""
    
    results, err := dkim.Verify(rawEmail)
    if err != nil {
        fmt.Println("DKIM verification failed! (%s)", err)
    } else {
        fmt.Println("DKIM Verified!")
    }
    
    for i, result := range results {
        fmt.Prinf("Dkim Header #%d: res=%s err=%s domain=%s\n", i, result.Result, result.Err, result.Domain)
    }
}
```

## Signing
`SimpleSign(rawMail, domain, selector, privateKeyPem string)` returns signed message in raw form and an error.
DNS TXT Record at `dkim._domainkey.example.com`:
```
v=DKIM1; k=rsa; p=MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALQcfOumlRZI4t1Wuk1rm4x0lDIHd2Lu58Lwk5CHq5w+UScq5A104PrXQ4dUL6R8mgTmizNE0oOXXM4nPA0PvysCAwEAAQ==
```
```go
package main

rawMail := ""

// Note: key must be in valid pksc pem format
exampleOrgKey := `-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBALQcfOumlRZI4t1Wuk1rm4x0lDIHd2Lu58Lwk5CHq5w+UScq5A10
4PrXQ4dUL6R8mgTmizNE0oOXXM4nPA0PvysCAwEAAQJAe3sofdr4TY3s03i5Q4jp
3LK0Q1RxGkfWZwTO9oC9O+EnWeFX0ZwtIfjP0WV5gGh+T1epg1tqMn85zbU5TLe8
IQIhAPuUgsTT2zvjSqWqKQTicQeoVRfQ+2WijWFf4+si0i1xAiEAt0aLPJorVDUp
ACWT/J//CGlgaAi+TCtj/dRtSloHGFsCIDU5aSUNER+taXh89GqlIXaWRVJhkx4g
crq8F7MCTebxAiEAl4P2cC90SrV4I+rtIRiUmrujO96elBH7JEmN4L30x6kCIQDV
Fl1FBwbvEE36bmwARayL0xAFxNrtfR6HbuUyEqIQqQ==
-----END RSA PRIVATE KEY-----`

signedMail, err := dkim.SimpleSign(rawMail, "example.org", "dkim", exampleOrgKey)
if err != nil {
    panic(err)
}
fmt.Printf("%#v\n", signedMail)
```

## Advanced Signing
`SimpleSign()` is ideal as it uses the best parameters for security and compatibility. However, for more fine grain control see the example below.
```go

package main

exampleOrgKey := `-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBALQcfOumlRZI4t1Wuk1rm4x0lDIHd2Lu58Lwk5CHq5w+UScq5A10
4PrXQ4dUL6R8mgTmizNE0oOXXM4nPA0PvysCAwEAAQJAe3sofdr4TY3s03i5Q4jp
3LK0Q1RxGkfWZwTO9oC9O+EnWeFX0ZwtIfjP0WV5gGh+T1epg1tqMn85zbU5TLe8
IQIhAPuUgsTT2zvjSqWqKQTicQeoVRfQ+2WijWFf4+si0i1xAiEAt0aLPJorVDUp
ACWT/J//CGlgaAi+TCtj/dRtSloHGFsCIDU5aSUNER+taXh89GqlIXaWRVJhkx4g
crq8F7MCTebxAiEAl4P2cC90SrV4I+rtIRiUmrujO96elBH7JEmN4L30x6kCIQDV
Fl1FBwbvEE36bmwARayL0xAFxNrtfR6HbuUyEqIQqQ==
-----END RSA PRIVATE KEY-----`

signPayload := dkim.SignPayload{
	"MIME-Version: 1.0\r\nDate: Fri, 24 May 2024 10:19:18 -0600\r\nReply-To: John.Doe@example.org\r\nSubject: Test Email\r\nFrom: John Doe <John.Doe@example.org>\r\nTo: alice@colorado.edu\r\nContent-Type: multipart/alternative; boundary=\"00000000000095c7110619358760\"\r\n\r\n--00000000000095c7110619358760\r\nContent-Type: text/plain; charset=\"UTF-8\"\r\n\r\nthis is a test email\r\n\r\n--00000000000095c7110619358760\r\nContent-Type: text/html; charset=\"UTF-8\"\r\n\r\n<div dir=\"ltr\">this is a test email</div>\r\n\r\n--00000000000095c7110619358760--",
	"example.org",
	"dkim",
	dkim.DefaultHeaders,
	dkim.Simple,
	dkim.Simple,
	time.Now().Unix(),
	time.Now().Add(1 * time.Hour).Unix(),
	exampleOrgPrivKey,
},

signedMail, err := signPayload.Sign()
if err != nil {
    panic(err)
}
fmt.Printf("%#v\n", signedMail)
```

## Support
The following can be checked by `Verify()`, but cannot be used in signing:
 - `rsa-sha1` signing algorithm (obsolete for signing)
 - Patial Signing `l=` (insecure)
 - Agent `i=` (havent gotten around to it)

The following is not supported:
 - `ed25519` signing algorithm (not supported YET, but planned feature)
 - copied header fields `z=` (ignored)
 - query method `q=` (ignored)

Everything in rfc that is not listed above should be supported.

## Notes
- It is up to the sender to correctly sign their emails. If the sender does not properly do this, emails can be spoofed even if DKIM verification passes.
- DKIM is extremely picky, thus it is not uncommon for DKIM to fail.
- DKIM is old and has flaws. DKIM is NOT a replacement for TLS. 
You should only ever send emails over TLS and never over an untrusted relay.


