# GoDKIM
A go module for verifying email with DKIM as described by RFC 6376.
**WORK IN PROGRESS**

## Verify
`Verify()` returns a slice of verifications results with one result for each signature. Verify also returns an error when verification has failed.

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
Signing is not yet supported.

## Notes
- It is up to the sender to correctly sign their emails. If the sender does not properly do this, emails can be spoofed even if DKIM verification passes.
- DKIM is extremely picky, thus it is not uncommon for DKIM to fail.
- DKIM is old and has flaws. DKIM is NOT a replacement for TLS. 
You should only ever send emails over TLS and never over an untrusted relay.


