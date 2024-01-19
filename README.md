# GoDKIM
A go module for singing and verifying email with DKIM as described by RFC 6376.
**WORK IN PROGRESS**

## Verifying an email
Example email:
```

```

Go code:
```go
package main

rawEmail := ""

/*
IMPORTANT NOTE!
The email must be in its completely raw form!
(including \r \n \t etc)
*/

err := dkim.VerifyEmailDKIM(rawEmail)
if err != nil {
    fmt.Println("DKIM verification failed! (%s)", err)
} else {
    fmt.Println("DKIM Verified!")
}
```

## Notes
- It is up to the sender to correctly sign their emails. If the sender does not properly do this, emails can be spoofed even if DKIM verification passes.
- DKIM is extremely picky, thus it is not uncommon for DKIM to fail.
- DKIM is old and has flaws. DKIM is NOT a replacement for TLS. 
You should only ever send emails over TLS and never over an untrusted relay.


