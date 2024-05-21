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

func VerifyEmail(rawEmail string) (err error) {
	dkimHeader, err := extractDKIMHeader(rawEmail)
	if err != nil {
		return err
	}

	dkimRecord, err := fetchDKIMRecord(dkimHeader.s, dkimHeader.d)
	if err != nil {
		return err
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
	headersCanonicalized, bodyCanonicalized, err := CanonicalizeEmail(dkimHeader.c, rawEmail)
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

	return
}
