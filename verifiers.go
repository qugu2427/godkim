package main

import (
	"fmt"
	"reflect"
	"strings"
	"time"
)

// Check that the dkim timestamp (t=) is not in the future. If no timestamp is specified, no error will be returned since it is not a required tag.
func (d *DKIMHeader) VerifyTimestamp() (err error) {
	if !d.t.IsZero() && d.t.After(time.Now()) {
		err = fmt.Errorf("dkim header timestamp in future")
		return
	}
	return
}

// Check that the dkim expiration (x=) is not in the past. If no expiration is specified, no error will be returned since it is not a required tag.
func (d *DKIMHeader) VerifyExpiration() (err error) {
	if !d.x.IsZero() && time.Now().After(d.x) {
		err = fmt.Errorf("dkim header expired")
		return
	}
	return
}

// Check that the dkim body hash (bh=) matches the hash of the *canonicalized* body
func (d *DKIMHeader) VerifyBodyHash(canonicalizedBody string) (err error) {
	if !strings.HasSuffix(canonicalizedBody, "\r\n") {
		canonicalizedBody += "\r\n"
	}

	// "canonicalized using the body canonicalization algorithm specified in the "c=" tag and then truncated to the length specified in the "l=" tag"
	if d.l > 0 {
		canonicalizedBody = canonicalizedBody[:d.l]
	}
	bodyHash, err := computeHash(d.a, []byte(canonicalizedBody))
	if err != nil {
		return
	}

	if !reflect.DeepEqual(bodyHash, d.bh) {
		err = fmt.Errorf("body hashes do not match")
		return
	}
	return
}

// Check that the signature (b=) matches the computed signature of headers
func (d *DKIMHeader) VerifySignature(dkimRecord DKIMRecord, canonicalizedHeaders string) (err error) {
	signatureMessage, err := buildSignatureMessage(d, canonicalizedHeaders, d.c.headerCanon)
	if err != nil {
		return err
	}
	err = checkSignature(d.a, dkimRecord.k, dkimRecord.p, signatureMessage, d.b)
	if err != nil {
		return err
	}
	return
}

type VerifyResult struct {
	Result VerificationResult
	Err    error
	Domain string
}

func Verify(rawMail string) (results []VerifyResult, err error) {
	dkimHeaders, err := extractDKIMHeaders(rawEmail)
	if err != nil {
		return nil, err
	}

	for _, dkimHeader := range dkimHeaders {
		var result VerifyResult
		result.Domain = dkimHeader.d

		var dkimRecord DKIMRecord
		dkimRecord, err = fetchDKIMRecord(dkimHeader.s, dkimHeader.d)
		if err != nil {
			result.Err = err
			result.Result = TempFail
		}

		// Check timestamp and expiration
		err = dkimHeader.VerifyTimestamp()
		if err != nil {
			result.Err = err
			result.Result = PermFail
		}
		err = dkimHeader.VerifyExpiration()
		if err != nil {
			result.Err = err
			result.Result = PermFail
		}

		// Canonicalize email
		var headersCanonicalized, bodyCanonicalized string
		headersCanonicalized, bodyCanonicalized, err = CanonicalizeEmail(dkimHeader.c, rawEmail)
		if err != nil {
			result.Err = err
			result.Result = PermFail
		}

		// Check body hash
		err = dkimHeader.VerifyBodyHash(bodyCanonicalized)
		if err != nil {
			result.Err = err
			result.Result = PermFail
		}

		// Check signature
		err = dkimHeader.VerifySignature(dkimRecord, headersCanonicalized)
		if err != nil {
			result.Err = err
			result.Result = PermFail
		}

		results = append(results, result)
	}

	return
}

func VerifySimple(rawMail string) (err error) {
	dkimHeaders, err := extractDKIMHeaders(rawEmail)
	if err != nil {
		return err
	}

	for _, dkimHeader := range dkimHeaders {
		var dkimRecord DKIMRecord
		dkimRecord, err = fetchDKIMRecord(dkimHeader.s, dkimHeader.d)
		if err != nil {
			return
		}

		// Check timestamp and expiration
		err = dkimHeader.VerifyTimestamp()
		if err != nil {
			return
		}
		err = dkimHeader.VerifyExpiration()
		if err != nil {
			return
		}

		// Canonicalize email
		var headersCanonicalized, bodyCanonicalized string
		headersCanonicalized, bodyCanonicalized, err = CanonicalizeEmail(dkimHeader.c, rawEmail)
		if err != nil {
			return
		}

		// Check body hash
		err = dkimHeader.VerifyBodyHash(bodyCanonicalized)
		if err != nil {
			return
		}

		// Check signature
		err = dkimHeader.VerifySignature(dkimRecord, headersCanonicalized)
		if err != nil {
			return
		}
	}

	return
}
