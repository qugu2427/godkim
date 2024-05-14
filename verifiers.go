package main

import (
	"fmt"
	"reflect"
	"time"
)

// Check that the dkim timestamp (t=) is not in the future. If no timestamp is specified, no error will be returned since it is not a required tag.
func (d *DKIMHeader) VerifyTimestamp() (err error) {
	if !d.t.IsZero() && d.t.After(time.Now()) {
		err = fmt.Errorf("timestamp is in the future")
		return
	}
	return
}

// Check that the dkim expiration (x=) is not in the past. If no expiration is specified, no error will be returned since it is not a required tag.
func (d *DKIMHeader) VerifyExpiration() (err error) {
	if !d.x.IsZero() && time.Now().After(d.x) {
		err = fmt.Errorf("expiration is in the past")
		return
	}
	return
}

// Check that the dkim body hash (bh=) matches the hash of the *canonicalized* body
func (d *DKIMHeader) VerifyBodyHash(canonicalizedBody string) (err error) {
	bodyHash, err := computeBodyHash(d.a, canonicalizedBody, d.l)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(bodyHash, d.bh) {
		err = fmt.Errorf("body hashes do not match")
		return
	}
	return
}

// FIXME
func (d *DKIMHeader) VerifySignature(dkimRecord DKIMDNSRecord, canonicalizedHeaders string) (err error) {
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
	dkimHeader, err := getDKIMHeaderFromEmail(rawEmail)
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
	// err = dkimHeader.VerifyExpiration()
	// if err != nil {
	// 	return
	// }

	// Canonicalize email
	headersCanonicalized, bodyCanonicalize, err := CanonicalizeEmail(dkimHeader.c, rawEmail)
	if err != nil {
		return
	}

	// Check body hash
	err = dkimHeader.VerifyBodyHash(bodyCanonicalize)
	if err != nil {
		return
	}

	// FIXME
	// Something wrong here
	err = dkimHeader.VerifySignature(dkimRecord, headersCanonicalized)
	if err != nil {
		return
	}

	return
}
