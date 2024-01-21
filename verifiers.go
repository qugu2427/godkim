package main

import (
	"fmt"
	"reflect"
	"time"
)

// Check the the dkim timestamp (t=) is not in the future. If no timestamp is specified, no error will be returned since it is not a required tag.
func VerifyTimestamp(dkimHeader DKIMHeader) (err error) {
	if !dkimHeader.t.IsZero() && dkimHeader.t.After(time.Now()) {
		err = fmt.Errorf("timestamp is in the future")
		return
	}
	return
}

// Check the the dkim expiration (x=) is not in the past. If no expiration is specified, no error will be returned since it is not a required tag.
func VerifyExpiration(dkimHeader DKIMHeader) (err error) {
	if !dkimHeader.x.IsZero() && time.Now().After(dkimHeader.x) {
		err = fmt.Errorf("expiration is in the past")
		return
	}
	return
}

func VerifyBodyHashAlreadyCanonicalized(dkimHeader DKIMHeader, canonicalizedBody string) (err error) {
	bodyHash, err := computeBodyHash(dkimHeader.a, dkimHeader.c.bodyCanon, canonicalizedBody, dkimHeader.l)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(bodyHash, dkimHeader.bh) {
		err = fmt.Errorf("body hashes do not match")
		return
	}
	return
}

func VerifySignature(dkimHeader DKIMHeader, dkimRecord DKIMDNSRecord, canonicalizedHeaders string) (err error) {
	signatureMessage, err := buildSignatureMessage(dkimHeader, canonicalizedHeaders, dkimHeader.c.headerCanon)
	if err != nil {
		return err
	}
	err = checkSignature(dkimHeader.a, dkimRecord.k, dkimRecord.p, signatureMessage, dkimHeader.b)
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
	fmt.Sprintf("%s", dkimRecord.n)

	// Check timestamp and expiration
	err = VerifyTimestamp(dkimHeader)
	if err != nil {
		return
	}
	err = VerifyExpiration(dkimHeader)
	if err != nil {
		return
	}

	// Canonicalize email
	headersCanonicalized, bodyCanonicalize, err := CanonicalizeEmail(dkimHeader.c, rawEmail)
	if err != nil {
		return
	}
	fmt.Sprintf("%s", headersCanonicalized)

	// Check body hash
	err = VerifyBodyHashAlreadyCanonicalized(dkimHeader, bodyCanonicalize)
	if err != nil {
		return
	}

	fmt.Printf("canon: %#v\n\n\n", headersCanonicalized)

	err = VerifySignature(dkimHeader, dkimRecord, headersCanonicalized)
	if err != nil {
		return
	}

	// Verify signature
	// signatureMessage, err := extractSignatureMessage(dkimHeader.c.headerCanon, dkimHeader.h, rawEmail)
	// if err != nil {
	// 	return
	// }
	// fmt.Printf("%#v\n", signatureMessage)
	// fmt.Println(signatureMessage)
	// err = checkSignature(dkimHeader.a, dkimRecord.k, dkimRecord.p, []byte(signatureMessage), dkimHeader.b)
	// if err != nil {
	// 	return
	// }

	return
}
